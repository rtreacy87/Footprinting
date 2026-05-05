from __future__ import annotations

import logging
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path

from .config import DnsReconConfig
from .models.attempt import Attempt
from .models.dns_record import DnsRecord
from .models.finding import Finding
from .models.pivot import Pivot
from .parsers.dig_parser import DigParser
from .parsers.zone_transfer_parser import ZoneTransferParser
from .reporting import build_attack_paths_report, build_findings_report, build_secure_findings_report
from .runners.dig_runner import DigRunner
from .runners.dnsenum_runner import DnsenumRunner
from .services.analysis_service import AnalysisService
from .services.baseline_service import BaselineService
from .services.recursion_service import RecursionService
from .services.reverse_dns_service import ReverseDnsService
from .services.subdomain_service import SubdomainService
from .services.version_disclosure_service import VersionDisclosureService
from .services.wildcard_service import WildcardService
from .services.zone_transfer_service import ZoneTransferService
from .writers.json_writer import JsonWriter
from .writers.markdown_writer import MarkdownWriter
from .writers.raw_writer import RawWriter
from .writers.summary_writer import SummaryWriter

logger = logging.getLogger(__name__)


def _discover_sub_zones(base_domain: str, records: list[DnsRecord]) -> list[str]:
    """Return FQDNs of A records that are sub-domains of base_domain.

    These are candidates for their own DNS zones. We skip the base domain
    itself and any record whose value is a loopback address (127.x.x.x).
    """
    base = base_domain.lower()
    candidates: list[str] = []
    for r in records:
        if r.record_type != "A":
            continue
        fqdn = r.fqdn.lower()
        if fqdn == base:
            continue
        if r.value.startswith("127."):
            continue
        if fqdn.endswith("." + base):
            candidates.append(fqdn)
    return candidates


@dataclass
class DnsReconResult:
    domain: str
    dns_server: str | None
    records: list[DnsRecord] = field(default_factory=list)
    attempts: list[Attempt] = field(default_factory=list)
    findings: list[Finding] = field(default_factory=list)
    pivots: list[Pivot] = field(default_factory=list)
    subdomains: list[DnsRecord] = field(default_factory=list)
    output_root: Path | None = None

    def all_records_flat(self) -> list[DnsRecord]:
        return self.records + self.subdomains

    def records_by_type(self, rtype: str) -> list[DnsRecord]:
        return [r for r in self.all_records_flat() if r.record_type == rtype]

    def zone_transfer_succeeded(self) -> bool:
        return any(a.category == "zone_transfer" and a.status == "success" for a in self.attempts)

    def name_servers(self) -> list[str]:
        return [r.value.rstrip(".") for r in self.records_by_type("NS")]

    def mail_servers(self) -> list[str]:
        mx_records = self.records_by_type("MX")
        results = []
        for r in mx_records:
            parts = r.value.split()
            results.append(parts[-1].rstrip(".") if len(parts) > 1 else r.value.rstrip("."))
        return results


class DnsOrchestrator:
    def __init__(self, config: DnsReconConfig) -> None:
        self._config = config
        self._setup_logging()

        timeout = config.timeout
        self._dig = DigRunner(timeout=timeout)
        self._dig_parser = DigParser()
        self._zt_parser = ZoneTransferParser()

        self._baseline_svc = BaselineService(self._dig, self._dig_parser)
        self._zt_svc = ZoneTransferService(self._dig, self._zt_parser)
        self._recursion_svc = RecursionService(self._dig)
        self._version_svc = VersionDisclosureService(self._dig)
        self._wildcard_svc = WildcardService(self._dig, self._dig_parser)
        self._subdomain_svc = SubdomainService(
            self._dig,
            self._dig_parser,
            DnsenumRunner(timeout=timeout * 6),
        )
        self._reverse_svc = ReverseDnsService(self._dig, self._dig_parser)
        self._analysis_svc = AnalysisService()

    def _setup_logging(self) -> None:
        level = logging.DEBUG if self._config.verbose else logging.INFO
        logging.basicConfig(
            format="%(asctime)s [%(levelname)s] %(name)s — %(message)s",
            level=level,
        )

    def run(self) -> DnsReconResult:
        cfg = self._config
        domain = cfg.domain.lower().rstrip(".")
        server = cfg.dns_server
        output_root = Path(cfg.output_root)

        raw_writer = RawWriter(output_root)
        json_writer = JsonWriter(output_root)
        md_writer = MarkdownWriter(output_root)
        summary_writer = SummaryWriter(output_root)

        result = DnsReconResult(
            domain=domain,
            dns_server=server,
            output_root=output_root,
        )

        started = datetime.now(timezone.utc).isoformat()
        json_writer.write_metadata("target.json", {"domain": domain, "dns_server": server})
        json_writer.write_metadata("scan_config.json", {
            "mode": cfg.mode,
            "timeout": cfg.timeout,
            "wordlist": cfg.wordlist,
            "tools": cfg.tools,
        })

        # Phase 2: Baseline records
        logger.info("=== Phase 2: Baseline DNS Records ===")
        baseline_records, raw_outputs = self._baseline_svc.run(domain, server=server)
        for rtype, raw in raw_outputs.items():
            raw_writer.write_dig(rtype, raw)
        for rtype, recs in baseline_records.items():
            result.records.extend(recs)
            json_writer.write_records(rtype, [r.to_dict() for r in recs])

        # Phase 3: Name server enumeration
        logger.info("=== Phase 3: Name Server Enumeration ===")
        ns_list = [r.value.rstrip(".") for r in result.records_by_type("NS")]
        # Always try the configured server IP first; NS hostnames may not resolve
        zt_servers = [server] if server else []
        json_writer.write("parsed/name_servers", "resolved.json", ns_list)

        # Phase 4: Zone transfer — base zone, then discovered sub-zones
        logger.info("=== Phase 4: Zone Transfer Testing ===")

        def _do_axfr(zone: str, servers: list[str]) -> list[DnsRecord]:
            zone_records: list[DnsRecord] = []
            for ns_addr in servers:
                zt_attempt, zt_records = self._zt_svc.attempt(zone=zone, nameserver=ns_addr)
                result.attempts.append(zt_attempt)
                result.records.extend(zt_records)
                zone_records.extend(zt_records)
                raw_writer.write_zone_transfer(ns_addr + "_" + zone.replace(".", "_"), zt_attempt.raw_output)
                if zt_attempt.status == "success" and zt_records:
                    for rtype in set(r.record_type for r in zt_records):
                        typed = [r for r in zt_records if r.record_type == rtype]
                        safe_zone = zone.replace(".", "_")
                        json_writer.write_records(
                            f"axfr_{safe_zone}_{rtype}",
                            [r.to_dict() for r in typed],
                        )
                    break  # stop after first successful transfer for this zone
            return zone_records

        base_zt_records = _do_axfr(domain, zt_servers)

        # Discover sub-zones: any A record that is a sub-domain of base domain
        # may have its own zone with additional records (e.g. internal.inlanefreight.htb)
        sub_zones = _discover_sub_zones(domain, base_zt_records)
        logger.info("Discovered %d sub-zone candidate(s): %s", len(sub_zones), sub_zones)
        for sub_zone in sorted(sub_zones):
            logger.info("=== Phase 4 (sub-zone): AXFR %s ===", sub_zone)
            _do_axfr(sub_zone, zt_servers)

        zt_attempts = [a for a in result.attempts if isinstance(a, Attempt)]
        json_writer.write_attempts("zone_transfer", [a.to_dict() for a in zt_attempts])

        # Phase 5: Recursion check
        logger.info("=== Phase 5: Recursion Check ===")
        check_server = server or (ns_list[0] if ns_list else None)
        if check_server:
            rec_attempt = self._recursion_svc.check(check_server)
            result.attempts.append(rec_attempt)
            json_writer.write_attempts("recursion", [rec_attempt.to_dict()])

        # Phase 6: Version disclosure
        logger.info("=== Phase 6: Version Disclosure ===")
        if check_server:
            ver_attempt = self._version_svc.check(check_server)
            result.attempts.append(ver_attempt)
            json_writer.write_attempts("version_disclosure", [ver_attempt.to_dict()])

        # Phase 7: Subdomain enumeration
        if cfg.mode in ("active", "full") and not cfg.skip_subdomain_brute:
            logger.info("=== Phase 7: Subdomain Enumeration ===")
            wildcard = self._wildcard_svc.check(domain, server=server)
            result.attempts.append(wildcard)
            json_writer.write_attempts("wildcard_detection", [wildcard.to_dict()])

            if wildcard.status not in ("success",) and cfg.wordlist:
                brute_records = self._subdomain_svc.brute_force(
                    domain=domain,
                    wordlist=cfg.wordlist,
                    server=server,
                    limit=cfg.bruteforce_limit,
                )
                result.subdomains.extend(brute_records)
                json_writer.write_subdomains("brute_force", [r.to_dict() for r in brute_records])

            all_subs = list({r.fqdn for r in result.subdomains})
            json_writer.write_subdomains("discovered", [{"fqdn": s} for s in all_subs])

        # Phase 9: Reverse DNS
        if cfg.ip_range and cfg.mode in ("active", "full"):
            logger.info("=== Phase 9: Reverse DNS ===")
            ptr_records = self._reverse_svc.sweep(cfg.ip_range, server=server)
            result.records.extend(ptr_records)
            json_writer.write("parsed/reverse_dns", "ptr_sweep.json", [r.to_dict() for r in ptr_records])

        # Phase 10: Analysis
        logger.info("=== Phase 10: Analysis ===")
        all_attempts_flat = [a for a in result.attempts if isinstance(a, Attempt)]
        findings, pivots = self._analysis_svc.analyze(result.all_records_flat(), all_attempts_flat)
        result.findings = findings
        result.pivots = pivots

        json_writer.write_analysis("infrastructure_map.json", {
            "name_servers": result.name_servers(),
            "mail_servers": result.mail_servers(),
            "subdomains": [r.fqdn for r in result.subdomains],
        })
        json_writer.write_analysis("potential_targets.json", [p.to_dict() for p in pivots])
        json_writer.write_analysis("risk_notes.json", [f.to_dict() for f in findings])

        pivot_by_type: dict[str, list[dict]] = {}
        for p in pivots:
            pivot_by_type.setdefault(p.pivot_type, []).append(p.to_dict())
        for ptype, plist in pivot_by_type.items():
            json_writer.write_pivots(ptype, plist)

        # Reports
        name_servers = result.name_servers()
        mail_servers = result.mail_servers()
        subdomain_names = [r.fqdn for r in result.subdomains]

        findings_md = build_findings_report(
            domain, result.all_records_flat(), findings, name_servers, mail_servers, subdomain_names
        )
        attack_md = build_attack_paths_report(findings, pivots, all_attempts_flat)
        secure_md = build_secure_findings_report(all_attempts_flat)

        md_writer.write("findings.md", findings_md)
        md_writer.write("attack_paths.md", attack_md)
        md_writer.write("secure_findings.md", secure_md)

        ended = datetime.now(timezone.utc).isoformat()
        json_writer.write_metadata("timestamps.json", {"started": started, "ended": ended})
        summary_writer.write_quick_view({
            "domain": domain,
            "dns_server": server,
            "total_records": len(result.all_records_flat()),
            "zone_transfer_succeeded": result.zone_transfer_succeeded(),
            "subdomains_found": len(result.subdomains),
            "findings_count": len(findings),
            "pivots_count": len(pivots),
            "output_root": str(output_root),
        })

        logger.info("DNS recon complete. Output: %s", output_root)
        return result
