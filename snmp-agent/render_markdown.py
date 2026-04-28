from __future__ import annotations
import json
from pathlib import Path
from typing import Any, Dict, List
from oid_maps import SECTION_TITLES


def _md_table(headers: List[str], rows: List[List[str]]) -> str:
    """
    Build a GitHub-flavored markdown table.
    Pipe characters in cell values are escaped with a backslash.
    """
    def escape(cell: str) -> str:
        return str(cell).replace("|", r"\|")

    header_row = "| " + " | ".join(escape(h) for h in headers) + " |"
    separator  = "| " + " | ".join("---" for _ in headers) + " |"
    lines = [header_row, separator]
    for row in rows:
        lines.append("| " + " | ".join(escape(str(cell)) for cell in row) + " |")
    return "\n".join(lines)


def render_readme(findings: Dict, metadata: Dict) -> str:
    """Render the top-level SNMP enumeration report as markdown."""
    ip = findings.get("asset", {}).get("ip", "unknown")
    identity = findings.get("system_identity", {})
    lines: List[str] = []

    lines.append(f"# SNMP Enumeration Report: {ip}\n")

    # Asset Summary
    lines.append("## Asset Summary\n")
    asset_rows = [
        ["IP",          ip],
        ["Hostname",    findings.get("asset", {}).get("hostname", "")],
        ["OS/Descr",    identity.get("sys_descr", "")[:120]],
        ["Contact",     identity.get("sys_contact", "")],
        ["Location",    identity.get("sys_location", "")],
        ["Uptime",      identity.get("uptime", "")],
    ]
    lines.append(_md_table(["Field", "Value"], asset_rows))
    lines.append("")

    # Collection Metadata
    lines.append("## Collection Metadata\n")
    meta_rows = [
        ["Collection Time", metadata.get("collected_at", "")],
        ["SNMP Version",    metadata.get("snmp_version", "")],
        ["Community Used",  metadata.get("community", "")],
        ["Tools Used",      ", ".join(metadata.get("tools_used", []))],
    ]
    lines.append(_md_table(["Field", "Value"], meta_rows))
    lines.append("")

    # High-Value Findings
    lines.append("## High-Value Findings\n")
    bullets: List[str] = []

    if findings.get("users_contacts"):
        bullets.append(
            f"- **Email addresses discovered:** {len(findings['users_contacts'])} "
            f"(see [suspicious findings](suspicious_findings.md))"
        )
    if findings.get("suspicious_strings"):
        bullets.append(
            f"- **Suspicious strings flagged:** {len(findings['suspicious_strings'])} "
            f"(see [suspicious findings](suspicious_findings.md))"
        )
    if findings.get("processes"):
        bullets.append(
            f"- **Running processes enumerated:** {len(findings['processes'])} "
            f"(see [services](services.md))"
        )
    if findings.get("installed_software"):
        bullets.append(
            f"- **Installed software packages:** {len(findings['installed_software'])} "
            f"(see [software](software.md))"
        )
    if findings.get("network_interfaces"):
        bullets.append(
            f"- **Network interfaces:** {len(findings['network_interfaces'])} "
            f"(see [network](network.md))"
        )
    if findings.get("ip_networking"):
        bullets.append(
            f"- **IP/routing entries:** {len(findings['ip_networking'])} "
            f"(see [network](network.md))"
        )
    if not bullets:
        bullets.append("- No high-value findings detected.")

    lines.extend(bullets)
    lines.append("")

    # Recommended Next Steps
    attack_paths = findings.get("potential_attack_paths", [])
    if attack_paths:
        lines.append("## Recommended Next Steps\n")
        for path in attack_paths:
            lines.append(f"- **{path.get('title', '')}**: {path.get('recommendation', '')}")
        lines.append("")
        lines.append(f"See [attack_paths.md](attack_paths.md) for full details.\n")

    return "\n".join(lines)


def render_system(findings: Dict) -> str:
    """Render system identity as a markdown key/value table."""
    identity = findings.get("system_identity", {})
    lines: List[str] = ["# System Identity\n"]

    if not identity:
        lines.append("_No system identity data collected._")
        return "\n".join(lines)

    rows = [[k, v] for k, v in identity.items()]
    lines.append(_md_table(["Key", "Value"], rows))
    return "\n".join(lines)


def render_network(findings: Dict) -> str:
    """Render network interfaces and IP/routing sections as markdown tables."""
    lines: List[str] = ["# Network Information\n"]

    interfaces = findings.get("network_interfaces", [])
    lines.append("## Interfaces\n")
    if interfaces:
        rows = [[e.get("oid", ""), e.get("name", ""), e.get("value", "")] for e in interfaces]
        lines.append(_md_table(["OID", "Name", "Value"], rows))
    else:
        lines.append("_No interface data collected._")
    lines.append("")

    ip_routing = findings.get("ip_networking", [])
    lines.append("## IP and Routing\n")
    if ip_routing:
        rows = [[e.get("oid", ""), e.get("name", ""), e.get("value", "")] for e in ip_routing]
        lines.append(_md_table(["OID", "Name", "Value"], rows))
    else:
        lines.append("_No IP/routing data collected._")
    lines.append("")

    return "\n".join(lines)


def render_services(findings: Dict) -> str:
    """Render TCP and UDP SNMP data as markdown tables."""
    lines: List[str] = ["# Service Information\n"]

    tcp_entries = findings.get("tcp", [])
    lines.append("## TCP Information\n")
    if tcp_entries:
        rows = [[e.get("oid", ""), e.get("name", ""), e.get("value", "")] for e in tcp_entries]
        lines.append(_md_table(["OID", "Name", "Value"], rows))
    else:
        lines.append("_No TCP data collected._")
    lines.append("")

    udp_entries = findings.get("udp", [])
    lines.append("## UDP Information\n")
    if udp_entries:
        rows = [[e.get("oid", ""), e.get("name", ""), e.get("value", "")] for e in udp_entries]
        lines.append(_md_table(["OID", "Name", "Value"], rows))
    else:
        lines.append("_No UDP data collected._")
    lines.append("")

    return "\n".join(lines)


def render_software(findings: Dict) -> str:
    """Render installed software as a markdown name/value table."""
    software = findings.get("installed_software", [])
    count = len(software)
    lines: List[str] = [f"# Installed Software ({count} entries)\n"]

    if not software:
        lines.append("_No installed software data collected._")
        return "\n".join(lines)

    rows = [[e.get("name", ""), e.get("value", "")] for e in software]
    lines.append(_md_table(["Name", "Value"], rows))
    return "\n".join(lines)


def render_suspicious(findings: Dict) -> str:
    """Render suspicious strings as a markdown table."""
    suspicious = findings.get("suspicious_strings", [])
    lines: List[str] = ["# Suspicious Findings\n"]

    if not suspicious:
        lines.append("_No suspicious strings flagged._")
        return "\n".join(lines)

    rows = [
        [
            s.get("name", ""),
            s.get("value", ""),
            s.get("reason", ""),
            SECTION_TITLES.get(s.get("section", ""), s.get("section", "")),
        ]
        for s in suspicious
    ]
    lines.append(_md_table(["Name", "Value", "Reason", "Section"], rows))
    return "\n".join(lines)


def render_attack_paths(findings: Dict) -> str:
    """Render potential attack paths as numbered H2 sections with evidence and recommendations."""
    paths = findings.get("potential_attack_paths", [])
    lines: List[str] = ["# Potential Attack Paths\n"]

    if not paths:
        lines.append("_No attack paths identified._")
        return "\n".join(lines)

    for i, path in enumerate(paths, start=1):
        title = path.get("title", f"Path {i}")
        lines.append(f"## {i}. {title}\n")

        evidence = path.get("evidence", [])
        if evidence:
            lines.append("**Evidence:**\n")
            for item in evidence:
                lines.append(f"- {item}")
            lines.append("")

        recommendation = path.get("recommendation", "")
        if recommendation:
            lines.append(f"**Recommendation:** {recommendation}\n")

    return "\n".join(lines)


def write_all(findings: Dict, metadata: Dict, markdown_dir: Path) -> None:
    """Write all markdown report files to markdown_dir."""
    markdown_dir.mkdir(parents=True, exist_ok=True)

    files = {
        "README.md":              render_readme(findings, metadata),
        "system.md":              render_system(findings),
        "network.md":             render_network(findings),
        "services.md":            render_services(findings),
        "software.md":            render_software(findings),
        "suspicious_findings.md": render_suspicious(findings),
        "attack_paths.md":        render_attack_paths(findings),
    }

    for filename, content in files.items():
        output_path = markdown_dir / filename
        output_path.write_text(content, encoding="utf-8")
