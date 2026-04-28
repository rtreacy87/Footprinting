"""Markdown report generator."""

from __future__ import annotations

from pathlib import Path

from ..config import Finding


def write_summary(path: Path, data: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    identity = data.get("identity", {})
    databases = data.get("databases", [])
    tables = data.get("tables", [])
    grants = data.get("grants", [])
    findings = data.get("findings", [])
    security_vars = data.get("security_variables", [])

    def _db_name(d: dict) -> str:
        return d.get("schema_name") or d.get("SCHEMA_NAME") or ""

    app_dbs = [d for d in databases if d.get("db_type") == "application"]
    app_tables = [t for t in tables if (t.get("table_schema") or t.get("TABLE_SCHEMA") or "")
                  not in {"information_schema", "mysql", "performance_schema", "sys"}]

    lines = [
        "# MySQL Enumeration Summary",
        "",
        "## Target",
        f"- **Host:** {data.get('target')}",
        f"- **Port:** {data.get('port')}",
        f"- **Version:** {identity.get('version', 'unknown')}",
        f"- **Server hostname:** {identity.get('server_hostname', 'unknown')}",
        f"- **Authenticated as:** {identity.get('login_user', 'unknown')}",
        f"- **Effective user:** {identity.get('effective_user', 'unknown')}",
        "",
        "## Databases",
        f"- Total visible: {len(databases)}",
        f"- Application databases: {len(app_dbs)}",
    ]

    for db in app_dbs:
        lines.append(f"  - `{_db_name(db)}`")

    lines += ["", "## Tables"]
    lines.append(f"- Application tables visible: {len(app_tables)}")

    lines += ["", "## Grants"]
    for grant in grants[:10]:
        lines.append(f"- `{grant}`")

    lines += ["", "## Security-Relevant Variables"]
    for var in security_vars:
        lines.append(f"- `{var.get('Variable_name')}` = `{var.get('Value')}`")

    severity_order = ["critical", "high", "medium", "low", "info"]
    lines += ["", "## Findings"]
    for severity in severity_order:
        sev_findings = [f for f in findings if f.get("severity") == severity]
        for f in sev_findings:
            lines.append(f"- **[{severity.upper()}]** {f.get('title')}")

    path.write_text("\n".join(lines), encoding="utf-8")


def write_findings(path: Path, findings: list[dict]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    severity_order = ["critical", "high", "medium", "low", "info"]
    lines = ["# MySQL Enumeration Findings", ""]

    for severity in severity_order:
        sev_findings = [f for f in findings if f.get("severity") == severity]
        if not sev_findings:
            continue
        lines.append(f"## {severity.capitalize()}")
        lines.append("")
        for f in sev_findings:
            lines.append(f"### {f.get('title')}")
            lines.append("")
            lines.append(f.get("description", ""))
            lines.append("")
            if f.get("recommendation"):
                lines.append(f"**Recommendation:** {f['recommendation']}")
                lines.append("")

    path.write_text("\n".join(lines), encoding="utf-8")


def write_llm_context(path: Path, data: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    identity = data.get("identity", {})
    databases = data.get("databases", [])
    tables = data.get("tables", [])
    grants = data.get("grants", [])
    findings = data.get("findings", [])
    security_vars = data.get("security_variables", [])
    high_value = data.get("high_value_tables", [])
    sensitive_cols = data.get("sensitive_columns", [])

    dangerous = [f for f in findings if f.get("severity") in ("critical", "high")]

    lines = [
        "# MySQL Enumeration Review Context",
        "",
        "## Target",
        f"- Host: {data.get('target')}",
        f"- Port: {data.get('port')}",
        f"- Version: {identity.get('version', 'unknown')}",
        f"- Authenticated as: {identity.get('login_user', 'unknown')}",
        "",
        "## Access Summary",
        f"- Databases visible: {len(databases)}",
        f"- Tables visible: {len(tables)}",
        "- Grants:",
    ]
    for g in grants[:5]:
        lines.append(f"  - `{g}`")

    if dangerous:
        lines += ["", "## Dangerous Findings"]
        for f in dangerous:
            lines.append(f"- **[{f['severity'].upper()}]** {f['title']}")

    if high_value:
        lines += ["", "## High-Value Tables"]
        lines.append("| Database | Table | Reason | Rows |")
        lines.append("|----------|-------|--------|------|")
        for t in high_value[:20]:
            lines.append(
                f"| {t.get('database')} | {t.get('table')} | {t.get('reason')} | {t.get('rows')} |"
            )

    if sensitive_cols:
        lines += ["", "## Sensitive Columns"]
        lines.append("| Database | Table | Column | Reason |")
        lines.append("|----------|-------|--------|--------|")
        for c in sensitive_cols[:30]:
            lines.append(
                f"| {c.get('database')} | {c.get('table')} | {c.get('column')} | {c.get('reason')} |"
            )

    if security_vars:
        lines += ["", "## Security-Relevant Variables"]
        lines.append("| Variable | Value |")
        lines.append("|----------|-------|")
        for v in security_vars:
            lines.append(f"| {v.get('Variable_name')} | {v.get('Value')} |")

    lines += ["", "## Recommended Next Steps"]
    lines.append("- Review high-value tables for sensitive data")
    lines.append("- Audit user privileges and wildcard hosts")
    lines.append("- Verify TLS configuration")
    lines.append("- Check file read/write capability via secure_file_priv and FILE privilege")

    path.write_text("\n".join(lines), encoding="utf-8")
