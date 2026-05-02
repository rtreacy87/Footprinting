from __future__ import annotations
from pathlib import Path

from ..config import ScanContext


class MarkdownReporter:
    def write(self, context: ScanContext) -> None:
        reports = context.config.output_base / context.target_host / "reports"
        reports.mkdir(parents=True, exist_ok=True)

        self._write_summary(context, reports / "summary.md")
        self._write_trace(context, reports / "decision_tree_trace.md")
        self._write_findings(context, reports / "findings.md")

    def _write_summary(self, context: ScanContext, path: Path) -> None:
        cred_rows = "\n".join(
            f"| {c.username} | {c.password} | {c.sid or ''} | {c.source} | {'Yes' if c.valid else 'No'} |"
            for c in context.valid_credentials
        )
        sid_rows = "\n".join(f"| {s} | SID | nmap |" for s in context.discovered_sids)

        post_auth = ""
        for key, data in context.post_auth_data.items():
            users = [r.get("username", "") for r in data.get("users", [])]
            post_auth += f"\n**{key}**: users={users[:5]}\n"
            if data.get("dbsnmp_hash"):
                for row in data["dbsnmp_hash"]:
                    post_auth += f"\n**DBSNMP hash**: spare4=`{row.get('spare4', 'N/A')}`\n"

        path.write_text(
            f"""# Oracle TNS Enumeration Summary

## Target

- Host: {context.target_host}
- Port: {context.target_port}
- Oracle TNS Detected: {context.tool_status.get("oracle_detected", "unknown")}

## SID / Service Name Discovery

| Identifier | Type | Source |
|---|---|---|
{sid_rows or "| (none discovered) | - | - |"}

## Authentication Results

| Username | Password | SID/Service | Source | Valid |
|---|---|---|---|---:|
{cred_rows or "| (none found) | - | - | - | No |"}

## Post-Authentication Enumeration
{post_auth or "(not run)"}

## Findings

{chr(10).join(f"- [{f.severity}] **{f.title}**: {f.description}" for f in context.findings) or "(none)"}
""",
            encoding="utf-8",
        )

    def _write_trace(self, context: ScanContext, path: Path) -> None:
        lines = "\n".join(f"{i+1}. {entry}" for i, entry in enumerate(context.decision_trace))
        path.write_text(f"# Decision Tree Trace\n\n{lines}\n", encoding="utf-8")

    def _write_findings(self, context: ScanContext, path: Path) -> None:
        sections = []
        for f in context.findings:
            evidence = "\n".join(f"  - {e}" for e in f.evidence)
            steps = "\n".join(f"- {s}" for s in f.recommended_next_steps)
            sections.append(
                f"""## {f.id}: {f.title}

- Severity: {f.severity}
- Category: {f.category}
- Evidence:
{evidence}

Recommended next steps:

{steps}
"""
            )
        path.write_text("# Findings\n\n" + "\n---\n\n".join(sections), encoding="utf-8")
