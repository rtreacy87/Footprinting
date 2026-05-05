from __future__ import annotations

import re

from ..models.attempt import Attempt
from ..models.dns_record import DnsRecord
from ..models.finding import Finding, Severity
from ..models.pivot import Pivot, PivotType

_CLOUD_PATTERNS = {
    "amazonaws.com": "AWS S3/EC2",
    "blob.core.windows.net": "Azure Blob",
    "storage.googleapis.com": "GCP Storage",
    "cloudfront.net": "AWS CloudFront",
    "azurewebsites.net": "Azure App Service",
}
_INTERNAL_LABELS = re.compile(r"\b(internal|intranet|corp|ad|dc\d*|ldap|vpn|dmz|mgmt|management)\b", re.IGNORECASE)
_DEV_LABELS = re.compile(r"\b(dev|staging|test|uat|qa|preprod|sandbox|demo)\b", re.IGNORECASE)
_SENSITIVE_TXT = re.compile(r"(password|secret|key|token|api[_-]?key|private)", re.IGNORECASE)
_HTB_FLAG = re.compile(r"HTB\{[^}]+\}")


class AnalysisService:
    def analyze(
        self,
        records: list[DnsRecord],
        attempts: list[Attempt],
    ) -> tuple[list[Finding], list[Pivot]]:
        findings: list[Finding] = []
        pivots: list[Pivot] = []

        self._analyze_zone_transfers(attempts, findings)
        self._analyze_recursion(attempts, findings)
        self._analyze_version(attempts, findings)
        self._analyze_records(records, findings, pivots)

        return findings, pivots

    def _analyze_zone_transfers(self, attempts: list[Attempt], findings: list[Finding]) -> None:
        for a in attempts:
            if a.category != "zone_transfer":
                continue
            if a.status == "success":
                findings.append(Finding(
                    title="Zone Transfer Allowed",
                    severity="high",
                    description=f"DNS zone transfer (AXFR) succeeded against {a.target}.",
                    evidence=[a.name],
                    recommendation="Restrict AXFR to trusted slave servers only.",
                ))

    def _analyze_recursion(self, attempts: list[Attempt], findings: list[Finding]) -> None:
        for a in attempts:
            if a.category != "recursion":
                continue
            if a.status == "success":
                findings.append(Finding(
                    title="Open DNS Recursion",
                    severity="medium",
                    description=f"DNS server {a.target} allows recursive queries from external clients.",
                    evidence=[a.name],
                    recommendation="Disable recursion for external clients.",
                ))

    def _analyze_version(self, attempts: list[Attempt], findings: list[Finding]) -> None:
        for a in attempts:
            if a.category != "version_disclosure":
                continue
            if a.status == "success":
                findings.append(Finding(
                    title="DNS Version Disclosed",
                    severity="low",
                    description=f"version.bind query revealed: {a.detail}",
                    evidence=[a.name],
                    recommendation="Set version to 'none' or 'not available' in BIND config.",
                ))

    def _analyze_records(
        self, records: list[DnsRecord], findings: list[Finding], pivots: list[Pivot]
    ) -> None:
        seen_pivots: set[str] = set()

        for rec in records:
            if rec.record_type == "MX":
                hostname = rec.value.split()[-1] if " " in rec.value else rec.value
                hostname = hostname.rstrip(".")
                if hostname not in seen_pivots:
                    seen_pivots.add(hostname)
                    pivots.append(Pivot(
                        hostname=hostname,
                        pivot_type="smtp",
                        source="MX record",
                        recommended_module="smtp_recon",
                    ))

            elif rec.record_type == "A":
                fqdn = rec.fqdn
                if _INTERNAL_LABELS.search(fqdn):
                    if fqdn not in seen_pivots:
                        seen_pivots.add(fqdn)
                        pivots.append(Pivot(
                            hostname=fqdn,
                            pivot_type="internal",
                            source="A record (internal label)",
                            recommended_module="smb_enum or nmap",
                            ip=rec.value,
                        ))
                if _DEV_LABELS.search(fqdn):
                    findings.append(Finding(
                        title="Dev/Staging Subdomain Exposed",
                        severity="contextual",
                        description=f"{fqdn} ({rec.value}) appears to be a dev/staging host.",
                        evidence=[f"{rec.record_type} {fqdn} -> {rec.value}"],
                        recommendation="Verify this host is intentionally public.",
                    ))
                    if fqdn not in seen_pivots:
                        seen_pivots.add(fqdn)
                        pivots.append(Pivot(
                            hostname=fqdn,
                            pivot_type="web",
                            source="A record (dev label)",
                            recommended_module="web_recon",
                            ip=rec.value,
                        ))

            elif rec.record_type == "CNAME":
                for pattern, name in _CLOUD_PATTERNS.items():
                    if pattern in rec.value:
                        findings.append(Finding(
                            title=f"Cloud Asset Reference: {name}",
                            severity="contextual",
                            description=f"{rec.fqdn} CNAME points to {name}: {rec.value}",
                            evidence=[f"CNAME {rec.fqdn} -> {rec.value}"],
                            recommendation="Verify cloud resource ownership to prevent subdomain takeover.",
                        ))
                        if rec.fqdn not in seen_pivots:
                            seen_pivots.add(rec.fqdn)
                            pivots.append(Pivot(
                                hostname=rec.fqdn,
                                pivot_type="cloud",
                                source="CNAME cloud reference",
                                recommended_module="web_recon",
                                notes=f"Points to {name}: {rec.value}",
                            ))

            elif rec.record_type == "TXT":
                if _SENSITIVE_TXT.search(rec.value):
                    findings.append(Finding(
                        title="Sensitive Data in TXT Record",
                        severity="medium",
                        description=f"TXT record for {rec.fqdn} may contain sensitive data.",
                        evidence=[f"TXT {rec.fqdn}: {rec.value[:100]}"],
                        recommendation="Remove sensitive data from public DNS TXT records.",
                    ))
                if _HTB_FLAG.search(rec.value):
                    findings.append(Finding(
                        title="HTB Flag Found in TXT Record",
                        severity="informational",
                        description=f"HTB flag in TXT record: {rec.fqdn}",
                        evidence=[rec.value],
                    ))
