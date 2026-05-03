from __future__ import annotations

from ..context import ScanContext
from ..core.enums import ControlStatus
from .report_registry import register_reporter
from .reporter import Reporter


@register_reporter("executive")
class ExecutiveReporter(Reporter):
    """Writes a non-technical executive summary."""

    def write(self, context: ScanContext) -> None:
        lines: list[str] = []
        lines.append("# Executive Summary: SMB Enumeration Assessment")
        lines.append("")
        lines.append(f"**Target:** `{context.target}`")
        lines.append(f"**Assessment Date:** See run metadata")
        lines.append("")

        failed = [c for c in context.control_assessments if c.status == ControlStatus.FAILED.value]
        passed = [c for c in context.control_assessments if c.status == ControlStatus.PASSED.value]

        # Overall risk
        if len(failed) == 0:
            risk_level = "LOW"
            risk_summary = "No critical SMB misconfigurations were identified during this assessment."
        elif len(failed) <= 2:
            risk_level = "MEDIUM"
            risk_summary = (
                f"{len(failed)} SMB security control(s) failed. "
                "Review the failed controls and attack paths below."
            )
        else:
            risk_level = "HIGH"
            risk_summary = (
                f"{len(failed)} SMB security controls failed. "
                "Immediate remediation is recommended."
            )

        lines.append(f"## Overall Risk: {risk_level}")
        lines.append(risk_summary)
        lines.append("")

        # Business impact
        lines.append("## Business Impact")
        impacts: list[str] = []
        if any(c.control_id == "CTRL-SMB-AUTH-001" for c in failed):
            impacts.append(
                "Anonymous users can list and browse SMB shares without authentication, "
                "potentially exposing sensitive business data."
            )
        if any(c.control_id in ("CTRL-SMB-SHARE-001", "CTRL-SMB-SHARE-002") for c in failed):
            impacts.append(
                "Files are accessible or writable without authentication, "
                "risking data theft or tampering."
            )
        if any(c.control_id == "CTRL-SMB-PROTO-001" for c in failed):
            impacts.append(
                "The lack of SMB signing allows network relay attacks that could "
                "enable an attacker to impersonate users or systems."
            )
        if any(c.control_id == "CTRL-SMB-PROTO-002" for c in failed):
            impacts.append(
                "SMBv1 is enabled, exposing the system to known critical exploits "
                "such as EternalBlue (MS17-010)."
            )
        if any(c.control_id in ("CTRL-SMB-DATA-001", "CTRL-SMB-DATA-002") for c in failed):
            impacts.append(
                "Credential files or backup archives are accessible via SMB, "
                "which could expose passwords or sensitive configuration data."
            )
        if impacts:
            for impact in impacts:
                lines.append(f"- {impact}")
        else:
            lines.append("No significant business impact identified based on available evidence.")
        lines.append("")

        # Key remediations
        lines.append("## Key Remediations")
        if failed:
            for c in failed:
                lines.append(f"- **{c.control_id} ({c.name}):** {c.reason}")
        else:
            lines.append("No remediations required — all tested controls passed.")
        lines.append("")

        # What appeared secure
        lines.append("## What Was Tested and Appeared Secure")
        if passed:
            for c in passed:
                lines.append(f"- **{c.control_id} ({c.name}):** {c.reason}")
        else:
            lines.append("No controls confirmed as passing during this assessment.")
        lines.append("")

        # Attack paths summary
        if context.attack_paths:
            lines.append("## Identified Attack Vectors")
            for ap in context.attack_paths:
                lines.append(f"- **{ap.title}** (confidence: {ap.confidence}): {ap.impact}")
            lines.append("")

        out_path = context.output_base / "summaries" / "executive_summary.md"
        out_path.parent.mkdir(parents=True, exist_ok=True)
        out_path.write_text("\n".join(lines), encoding="utf-8")
