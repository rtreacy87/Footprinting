from __future__ import annotations

import logging
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from ..models.finding import Finding
from ..models.result import CheckResult
from ..models.scan_context import ScanContext

logger = logging.getLogger(__name__)

_SEVERITY_EMOJI = {
    "critical": "CRITICAL",
    "high": "HIGH",
    "medium": "MEDIUM",
    "low": "LOW",
    "info": "INFO",
}


class MarkdownWriter:
    """Write a human-readable Markdown report."""

    def write(
        self,
        context: ScanContext,
        results: list[CheckResult],
        all_findings: list[Finding],
        attack_paths: list[Any],
    ) -> Path:
        out_path = context.target_dir / "report" / "smtp_recon_report.md"
        out_path.parent.mkdir(parents=True, exist_ok=True)

        lines: list[str] = []
        now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")

        lines += [
            f"# SMTP Reconnaissance Report",
            f"",
            f"**Target:** `{context.target.ip}`  ",
            f"**Domain:** `{context.target.domain or 'N/A'}`  ",
            f"**Scanned:** {now}  ",
            f"**Safe Mode:** {'Yes' if context.safe_mode else 'No'}  ",
            f"",
            "---",
            "",
            "## Summary",
            "",
            f"- Open SMTP ports: {context.open_ports or 'none detected'}",
            f"- Checks run: {len(results)}",
            f"- Total findings: {len(all_findings)}",
            f"- Critical: {len([f for f in all_findings if f.severity == 'critical'])}",
            f"- High: {len([f for f in all_findings if f.severity == 'high'])}",
            f"- Medium: {len([f for f in all_findings if f.severity == 'medium'])}",
            "",
            "---",
            "",
            "## Check Results",
            "",
        ]

        for result in results:
            status_icon = {"success": "[+]", "failed": "[!]", "skipped": "[-]",
                           "blocked": "[~]", "inconclusive": "[?]"}.get(result.status, "[?]")
            lines += [
                f"### {status_icon} {result.name}",
                f"",
                f"**Status:** {result.status}  ",
                f"**Summary:** {result.summary}  ",
            ]
            if result.errors:
                lines += ["**Errors:**"]
                for err in result.errors:
                    lines.append(f"- `{err}`")
            lines.append("")

        lines += [
            "---",
            "",
            "## Findings",
            "",
        ]

        if not all_findings:
            lines.append("_No findings recorded._")
            lines.append("")
        else:
            for finding in sorted(
                all_findings,
                key=lambda f: ["critical", "high", "medium", "low", "info"].index(f.severity)
                if f.severity in ["critical", "high", "medium", "low", "info"] else 99,
            ):
                sev_label = _SEVERITY_EMOJI.get(finding.severity, finding.severity.upper())
                lines += [
                    f"### [{sev_label}] {finding.title}",
                    f"",
                    f"**Category:** {finding.category}  ",
                    f"**Port:** {finding.port if finding.port else 'N/A'}  ",
                    f"",
                    f"{finding.description}",
                    f"",
                ]
                if finding.evidence:
                    lines += [
                        "**Evidence:**",
                        "```",
                        finding.evidence[:1000],
                        "```",
                        "",
                    ]
                if finding.remediation:
                    lines += [
                        f"**Remediation:** {finding.remediation}",
                        "",
                    ]
                lines.append("---")
                lines.append("")

        lines += [
            "## Attack Paths",
            "",
        ]

        if not attack_paths:
            lines.append("_No attack paths identified._")
        else:
            for i, action in enumerate(attack_paths, 1):
                if hasattr(action, "action"):
                    lines += [
                        f"### {i}. [{action.priority.upper()}] {action.action}",
                        f"",
                        f"**Rationale:** {action.rationale}  ",
                    ]
                    if action.prerequisites:
                        lines.append(f"**Prerequisites:** {', '.join(action.prerequisites)}")
                    if action.tool_hint:
                        lines += [
                            "**Tool hint:**",
                            f"```",
                            action.tool_hint,
                            "```",
                        ]
                    lines.append("")

        out_path.write_text("\n".join(lines), encoding="utf-8")
        logger.info("[markdown_writer] Wrote report to %s", out_path)
        return out_path
