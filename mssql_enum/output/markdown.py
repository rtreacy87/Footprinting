"""Generate human-readable Markdown reports from enumeration data."""

from __future__ import annotations

from pathlib import Path


def write_summary(path: Path, data: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    identity = data.get("identity", {})
    auth = data.get("auth_context", {})
    dbs = data.get("non_default_databases", [])
    findings = data.get("findings", [])

    lines = [
        f"# MSSQL Enumeration Summary: {data.get('target', 'unknown')}",
        "",
        "## Identity",
        "",
        f"- **Hostname**: {identity.get('machine_name', 'N/A')}",
        f"- **Server Name**: {identity.get('server_name', 'N/A')}",
        f"- **Instance**: {identity.get('instance_name') or 'MSSQLSERVER (default)'}",
        f"- **Edition**: {identity.get('edition', 'N/A')}",
        f"- **Version**: {identity.get('product_version', 'N/A')}",
        f"- **Port**: {data.get('port', 1433)}",
        "",
        "## Auth Context",
        "",
        f"- **Auth Mode**: {data.get('auth_mode', 'sql')}",
        f"- **Login**: {auth.get('system_user', 'N/A')}",
        f"- **Effective User**: {auth.get('current_user', 'N/A')}",
        f"- **Sysadmin**: {'yes' if auth.get('is_sysadmin') == 1 else 'no'}",
        "",
        "## Non-Default Databases",
        "",
    ]

    if dbs:
        for db in dbs:
            lines.append(f"- **{db['name']}** — state: {db.get('state_desc', 'N/A')}, trustworthy: {bool(db.get('is_trustworthy_on'))}")
    else:
        lines.append("- None found or insufficient privileges")

    lines += ["", "## Findings", ""]
    if findings:
        for f in findings:
            lines.append(f"### [{f['severity'].upper()}] {f['title']}")
            lines.append(f"{f['description']}")
            if f.get("recommended_manual_check"):
                lines.append(f"**Follow-up**: {f['recommended_manual_check']}")
            lines.append("")
    else:
        lines.append("No automated findings generated.")

    path.write_text("\n".join(lines), encoding="utf-8")


def write_findings(path: Path, findings: list[dict]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    lines = ["# MSSQL Security Findings", ""]
    for f in findings:
        lines += [
            f"## [{f['severity'].upper()}] {f['title']}",
            f"**ID**: {f['id']}  **Category**: {f['category']}",
            "",
            f"{f['description']}",
            "",
        ]
        if f.get("recommended_manual_check"):
            lines.append(f"**Recommended Check**: {f['recommended_manual_check']}")
            lines.append("")
    path.write_text("\n".join(lines), encoding="utf-8")
