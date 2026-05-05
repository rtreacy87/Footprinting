#!/usr/bin/env python3
"""
HTB Footprinting — DNS lab solver.

Usage:
    python dns_footprint_solver.py <target_ip> [options]

The target IP rotates when the lab respawns; pass it explicitly each run.
"""

import argparse
import re
import sys
from pathlib import Path
from typing import Optional

import dns.exception
import dns.query
import dns.resolver

from dns_recon import DnsOrchestrator, DnsReconConfig
from dns_recon.models.dns_record import DnsRecord


_HTB_FLAG = re.compile(r"HTB\{[^}]+\}")


def _find_flag(records: list[DnsRecord]) -> Optional[str]:
    for r in records:
        if r.record_type == "TXT":
            m = _HTB_FLAG.search(r.value)
            if m:
                return m.group(0)
    return None


def _find_dc1_ip(domain: str, records: list[DnsRecord]) -> Optional[str]:
    candidates = [f"dc1.{domain}", f"dc1.internal.{domain}", "dc1"]
    for fqdn in candidates:
        for r in records:
            if r.record_type == "A" and r.fqdn == fqdn:
                return r.value
    for r in records:
        if r.record_type == "A" and r.fqdn.startswith("dc1."):
            return r.value
    return None


def _find_octet_203_host(records: list[DnsRecord]) -> Optional[str]:
    for r in records:
        if r.record_type != "A":
            continue
        parts = r.value.split(".")
        if len(parts) == 4 and parts[-1] == "203":
            return r.fqdn
    return None


def _find_dns_fqdn(target_ip: str, records: list[DnsRecord], ns_list: list[str]) -> Optional[str]:
    for r in records:
        if r.record_type == "A" and r.value == target_ip and r.fqdn in ns_list:
            return r.fqdn
    return ns_list[0] if ns_list else None


def _make_resolver(server: str, timeout: float) -> dns.resolver.Resolver:
    r = dns.resolver.Resolver(configure=False)
    r.nameservers = [server]
    r.timeout = timeout
    r.lifetime = timeout
    return r


def _brute_find_octet_203(
    server: str,
    zones: list[str],
    wordlist_path: Path,
    limit: int,
    timeout: float,
) -> Optional[str]:
    """Brute-force sub-domains looking for a host whose IP ends in .203.

    Wildcard DNS zones return a fixed IP for unknown names; that IP typically
    won't end in .203, so specifically checking the last octet still works
    in a wildcard environment.
    """
    if not wordlist_path.exists():
        return None

    words: list[str] = []
    for line in wordlist_path.read_text(errors="ignore").splitlines():
        w = line.strip()
        if w and not w.startswith("#"):
            words.append(w)
            if len(words) >= limit:
                break

    resolver = _make_resolver(server, timeout)
    for zone in zones:
        for word in words:
            fqdn = f"{word}.{zone}".lower()
            try:
                ans = resolver.resolve(fqdn, "A")
                for rdata in ans:
                    ip = rdata.to_text().strip()
                    if ip.split(".")[-1] == "203":
                        return fqdn
            except Exception:
                continue
    return None


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Solve HTB Footprinting DNS lab",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    parser.add_argument("target", help="Target DNS server IP (rotates on lab reset)")
    parser.add_argument("--domain", default="inlanefreight.htb", help="Base domain")
    parser.add_argument("--timeout", type=int, default=5, help="DNS query timeout (seconds)")
    parser.add_argument(
        "--wordlist",
        default="/usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt",
        help="Wordlist for subdomain brute-force",
    )
    parser.add_argument("--bruteforce-limit", type=int, default=5000, help="Max brute-force words")
    parser.add_argument("--no-bruteforce", action="store_true", help="Skip subdomain brute-force")
    parser.add_argument(
        "--output",
        default="dns_recon_output",
        help="Output directory for full recon artifacts",
    )
    parser.add_argument("--verbose", action="store_true", help="Verbose logging")
    args = parser.parse_args()

    wordlist = None if args.no_bruteforce else args.wordlist

    config = DnsReconConfig(
        domain=args.domain,
        dns_server=args.target,
        wordlist=wordlist,
        mode="full",
        output_root=args.output,
        timeout=args.timeout,
        bruteforce_limit=args.bruteforce_limit,
        skip_subdomain_brute=args.no_bruteforce,
        verbose=args.verbose,
    )

    orchestrator = DnsOrchestrator(config)
    result = orchestrator.run()

    all_records = result.all_records_flat()
    ns_list = result.name_servers()

    dns_fqdn = _find_dns_fqdn(args.target, all_records, ns_list)
    flag = _find_flag(all_records)
    dc1_ip = _find_dc1_ip(args.domain.lower().rstrip("."), all_records)
    host_203 = _find_octet_203_host(all_records)

    # Brute-force fallback: wildcard zones mask resolution results, but a host
    # with a real .203 IP will still return .203 (the wildcard IP won't).
    if host_203 is None and wordlist and not args.no_bruteforce:
        brute_zones = [args.domain.lower().rstrip(".")]
        # Also search sub-zones discovered via zone transfer
        brute_zones += sorted({
            r.fqdn for r in all_records
            if r.record_type == "A"
            and r.fqdn != args.domain.lower().rstrip(".")
            and r.fqdn.endswith("." + args.domain.lower().rstrip("."))
            and not r.value.startswith("127.")
        })
        print(f"\n[*] Brute-forcing .203 host across {len(brute_zones)} zone(s)...")
        host_203 = _brute_find_octet_203(
            server=args.target,
            zones=brute_zones,
            wordlist_path=Path(args.wordlist),
            limit=args.bruteforce_limit,
            timeout=float(args.timeout),
        )

    print()
    print("=" * 50)
    print("HTB DNS Lab Answers")
    print("=" * 50)
    print(f"Target DNS FQDN:          {dns_fqdn or 'NOT_FOUND'}")
    print(f"Zone Transfer TXT Flag:   {flag or 'NOT_FOUND'}")
    print(f"DC1 IPv4:                 {dc1_ip or 'NOT_FOUND'}")
    print(f"Host FQDN with .203 IP:   {host_203 or 'NOT_FOUND'}")
    print("=" * 50)
    print(f"Full recon output:        {args.output}/")

    missing = sum(1 for v in [dns_fqdn, flag, dc1_ip, host_203] if v is None)
    if missing:
        print(f"\n[!] {missing} answer(s) not found. Check {args.output}/summary/findings.md")
        return 1

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
