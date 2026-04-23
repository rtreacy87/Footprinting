#!/usr/bin/env python3

import argparse
import re
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Set, Tuple

import dns.exception
import dns.query
import dns.resolver
import dns.zone


def make_resolver(server: str, timeout: float) -> dns.resolver.Resolver:
    r = dns.resolver.Resolver(configure=False)
    r.nameservers = [server]
    r.timeout = timeout
    r.lifetime = timeout
    return r


def query_text(resolver: dns.resolver.Resolver, name: str, rrtype: str) -> List[str]:
    try:
        ans = resolver.resolve(name, rrtype)
    except Exception:
        return []
    return [r.to_text().strip().strip('"') for r in ans]


def safe_axfr(server: str, zone_name: str, timeout: float) -> Optional[dns.zone.Zone]:
    try:
        xfr = dns.query.xfr(server, zone_name, lifetime=timeout)
        zone = dns.zone.from_xfr(xfr)
        return zone
    except Exception:
        return None


def zone_records(zone: dns.zone.Zone, zone_name: str) -> List[Tuple[str, str, str]]:
    records: List[Tuple[str, str, str]] = []
    for name, node in zone.nodes.items():
        owner = str(name)
        fqdn = zone_name if owner == "@" else f"{owner}.{zone_name}"
        for rdataset in node.rdatasets:
            rrtype = dns.rdatatype.to_text(rdataset.rdtype)
            for rr in rdataset:
                records.append((fqdn.lower(), rrtype, rr.to_text().strip().strip('"')))
    return records


def find_dns_fqdn(target_ip: str, domain: str, resolver: dns.resolver.Resolver) -> Optional[str]:
    ns_records = query_text(resolver, domain, "NS")
    if not ns_records:
        return None

    # Prefer NS whose A points to target IP, else fall back to first NS.
    for ns in ns_records:
        ns_fqdn = ns.rstrip(".").lower()
        a_records = query_text(resolver, ns_fqdn, "A")
        if target_ip in a_records:
            return ns_fqdn
    return ns_records[0].rstrip(".").lower()


def discover_candidate_zones(base_domain: str, base_records: List[Tuple[str, str, str]]) -> Set[str]:
    zones = {base_domain.lower()}

    for fqdn, rrtype, value in base_records:
        if rrtype != "A":
            continue
        if fqdn == base_domain.lower():
            continue
        # Any delegated-looking subdomain is worth trying as a zone.
        zones.add(fqdn)

    return zones


def find_flag_txt(all_records: Dict[str, List[Tuple[str, str, str]]]) -> Optional[str]:
    pattern = re.compile(r"HTB\{[^}]+\}")
    for recs in all_records.values():
        for _, rrtype, value in recs:
            if rrtype == "TXT":
                m = pattern.search(value)
                if m:
                    return m.group(0)
    return None


def find_dc1_ip(domain: str, resolver: dns.resolver.Resolver, all_records: Dict[str, List[Tuple[str, str, str]]]) -> Optional[str]:
    # Direct queries first.
    candidates = [
        f"dc1.{domain}",
        f"dc1.internal.{domain}",
        "dc1",
    ]
    for name in candidates:
        ips = query_text(resolver, name, "A")
        if ips:
            return ips[0]

    # Fallback to zone records.
    for recs in all_records.values():
        for fqdn, rrtype, value in recs:
            if rrtype == "A" and fqdn.startswith("dc1."):
                return value
    return None


def find_octet_203_from_records(all_records: Dict[str, List[Tuple[str, str, str]]]) -> Optional[str]:
    for recs in all_records.values():
        for fqdn, rrtype, value in recs:
            if rrtype != "A":
                continue
            parts = value.split(".")
            if len(parts) == 4 and parts[-1] == "203":
                return fqdn
    return None


def brute_find_octet_203(
    resolver: dns.resolver.Resolver,
    zones: Iterable[str],
    wordlist_path: Path,
    limit: int,
) -> Optional[str]:
    if not wordlist_path.exists():
        return None

    words: List[str] = []
    for line in wordlist_path.read_text(errors="ignore").splitlines():
        w = line.strip()
        if not w or w.startswith("#"):
            continue
        words.append(w)
        if len(words) >= limit:
            break

    for zone in zones:
        for w in words:
            fqdn = f"{w}.{zone}".lower()
            ips = query_text(resolver, fqdn, "A")
            for ip in ips:
                parts = ip.split(".")
                if len(parts) == 4 and parts[-1] == "203":
                    return fqdn
    return None


def main() -> int:
    parser = argparse.ArgumentParser(description="Solve HTB DNS host-based enumeration lab")
    parser.add_argument("target", help="Target DNS server IP")
    parser.add_argument("--domain", default="inlanefreight.htb", help="Base domain")
    parser.add_argument("--timeout", type=float, default=3.0, help="DNS timeout seconds")
    parser.add_argument(
        "--wordlist",
        default="/usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt",
        help="Wordlist used for optional brute-force",
    )
    parser.add_argument("--bruteforce-limit", type=int, default=5000, help="Max words for brute-force")
    parser.add_argument("--no-bruteforce", action="store_true", help="Disable brute-force fallback")
    args = parser.parse_args()

    domain = args.domain.lower().rstrip(".")
    resolver = make_resolver(args.target, args.timeout)

    dns_fqdn = find_dns_fqdn(args.target, domain, resolver)

    all_records: Dict[str, List[Tuple[str, str, str]]] = {}
    base_zone = safe_axfr(args.target, domain, args.timeout)
    if base_zone is not None:
        all_records[domain] = zone_records(base_zone, domain)
    else:
        all_records[domain] = []

    candidate_zones = discover_candidate_zones(domain, all_records[domain])

    # Attempt AXFR on candidate sub-zones as well.
    for z in sorted(candidate_zones):
        if z == domain:
            continue
        zf = safe_axfr(args.target, z, args.timeout)
        if zf is not None:
            all_records[z] = zone_records(zf, z)

    flag = find_flag_txt(all_records)
    dc1_ip = find_dc1_ip(domain, resolver, all_records)
    host_203 = find_octet_203_from_records(all_records)

    if host_203 is None and not args.no_bruteforce:
        host_203 = brute_find_octet_203(
            resolver,
            sorted(candidate_zones),
            Path(args.wordlist),
            args.bruteforce_limit,
        )

    print(f"Target DNS FQDN: {dns_fqdn or 'NOT_FOUND'}")
    print(f"Zone Transfer TXT Flag: {flag or 'NOT_FOUND'}")
    print(f"DC1 IPv4: {dc1_ip or 'NOT_FOUND'}")
    print(f"Host FQDN with .203 IP: {host_203 or 'NOT_FOUND'}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
