from __future__ import annotations

from ..models.dns_record import DnsRecord
from ..models.finding import Finding


def build_findings_report(
    domain: str,
    records: list[DnsRecord],
    findings: list[Finding],
    name_servers: list[str],
    mail_servers: list[str],
    subdomains: list[str],
) -> str:
    lines = ["# DNS Recon Findings", "", f"## Target", f"- Domain: `{domain}`", ""]

    lines += ["## Records Found", ""]
    by_type: dict[str, list[DnsRecord]] = {}
    for r in records:
        by_type.setdefault(r.record_type, []).append(r)
    for rtype, recs in sorted(by_type.items()):
        lines.append(f"### {rtype}")
        for rec in recs:
            lines.append(f"- `{rec.fqdn}` → `{rec.value}`")
        lines.append("")

    lines += ["## Name Servers", ""]
    for ns in name_servers:
        lines.append(f"- `{ns}`")
    lines.append("")

    lines += ["## Mail Servers", ""]
    for mx in mail_servers:
        lines.append(f"- `{mx}`")
    lines.append("")

    lines += ["## Subdomains Found", ""]
    for sd in sorted(set(subdomains)):
        lines.append(f"- `{sd}`")
    lines.append("")

    lines += ["## Misconfigurations", ""]
    high_findings = [f for f in findings if f.severity in ("high", "critical")]
    if high_findings:
        for f in high_findings:
            lines.append(f"### {f.title} [{f.severity.upper()}]")
            lines.append(f.description)
            if f.evidence:
                lines.append("**Evidence:**")
                for e in f.evidence:
                    lines.append(f"- `{e}`")
            if f.recommendation:
                lines.append(f"**Recommendation:** {f.recommendation}")
            lines.append("")
    else:
        lines.append("No high-severity misconfigurations found.")
        lines.append("")

    lines += ["## Notable Metadata", ""]
    medium_findings = [f for f in findings if f.severity not in ("high", "critical")]
    for f in medium_findings:
        lines.append(f"- **{f.title}** ({f.severity}): {f.description}")
    lines.append("")

    lines += ["## Recommended Next Steps", ""]
    if any(f.severity in ("high", "critical") for f in findings):
        lines.append("- Investigate zone transfer exposure immediately")
    lines.append("- Enumerate mail servers via smtp_recon")
    lines.append("- Web-probe any discovered subdomains")
    lines.append("- Run SMB/LDAP enumeration against internal hosts")

    return "\n".join(lines)
