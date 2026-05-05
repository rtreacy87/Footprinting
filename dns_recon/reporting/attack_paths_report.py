from __future__ import annotations

from ..models.attempt import Attempt
from ..models.finding import Finding
from ..models.pivot import Pivot


def build_attack_paths_report(
    findings: list[Finding],
    pivots: list[Pivot],
    attempts: list[Attempt],
) -> str:
    lines = ["# DNS-Derived Attack Paths", ""]

    path_num = 1

    zt_success = [a for a in attempts if a.category == "zone_transfer" and a.status == "success"]
    for zt in zt_success:
        lines += [
            f"## Path {path_num}: Zone Transfer Exposure",
            f"Zone transfer succeeded against `{zt.target}`.",
            f"This exposes the full zone contents and reveals internal infrastructure.",
            "",
        ]
        path_num += 1

    smtp_pivots = [p for p in pivots if p.pivot_type == "smtp"]
    for p in smtp_pivots:
        lines += [
            f"## Path {path_num}: MX Record to SMTP Recon",
            f"`{p.hostname}` was discovered through MX records.",
            f"Recommended next module: `{p.recommended_module}`",
            "",
        ]
        path_num += 1

    web_pivots = [p for p in pivots if p.pivot_type == "web"]
    for p in web_pivots:
        lines += [
            f"## Path {path_num}: Dev Subdomain to Web Recon",
            f"`{p.hostname}` ({p.source}) appears to be a web-accessible target.",
            f"IP: {p.ip or 'unknown'} — Recommended next module: `{p.recommended_module}`",
            "",
        ]
        path_num += 1

    internal_pivots = [p for p in pivots if p.pivot_type == "internal"]
    for p in internal_pivots:
        lines += [
            f"## Path {path_num}: Internal Host to Network Recon",
            f"`{p.hostname}` ({p.ip}) appears to be an internal host.",
            f"Recommended next module: `{p.recommended_module}`",
            "",
        ]
        path_num += 1

    recursion_findings = [a for a in attempts if a.category == "recursion" and a.status == "success"]
    for a in recursion_findings:
        lines += [
            f"## Path {path_num}: Open Recursion Abuse",
            f"DNS server `{a.target}` allows open recursion.",
            "Can be used for DNS amplification or to pivot internal queries.",
            "",
        ]
        path_num += 1

    if path_num == 1:
        lines.append("No attack paths identified.")

    return "\n".join(lines)
