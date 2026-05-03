from __future__ import annotations

from ..context import ScanContext
from ..core.enums import ControlStatus, TestStatus
from .report_registry import register_reporter
from .reporter import Reporter


@register_reporter("markdown")
class MarkdownReporter(Reporter):
    """Writes smb_summary.md and smb_controls.md."""

    def write(self, context: ScanContext) -> None:
        self._write_summary(context)
        self._write_controls(context)

    # ------------------------------------------------------------------
    # smb_summary.md
    # ------------------------------------------------------------------

    def _write_summary(self, context: ScanContext) -> None:
        lines: list[str] = []
        lines.append("# SMB Enumeration Summary")
        lines.append("")
        lines.append(f"**Target:** `{context.target}`")
        lines.append(f"**Profile:** `{context.config.profile.value}`")
        lines.append(f"**Domain:** `{context.domain or 'unknown'}`")
        lines.append("")

        # Protocol info
        lines.append("## Protocol Information")
        proto = context.protocol_info
        if proto:
            lines.append(f"- **SMB Versions:** {', '.join(proto.smb_versions) if proto.smb_versions else 'unknown'}")
            lines.append(f"- **Signing Enabled:** {proto.signing_enabled}")
            lines.append(f"- **Signing Required:** {proto.signing_required}")
            lines.append(f"- **SMBv1 Enabled:** {proto.smb1_enabled}")
            lines.append(f"- **Dialect:** {proto.dialect or 'unknown'}")
        else:
            lines.append("- No protocol information collected.")
        if context.smb_version_banner:
            lines.append(f"- **Banner:** `{context.smb_version_banner}`")
        lines.append("")

        # Authentication results
        lines.append("## Authentication Results")
        for test_id in ("AUTH-001", "AUTH-002", "AUTH-003"):
            tr = context.get_test_result(test_id)
            if tr:
                icon = "VULNERABLE" if tr.status == TestStatus.PASSED_VULNERABLE.value else (
                    "SECURE" if tr.status == TestStatus.FAILED_SECURE.value else "INCONCLUSIVE"
                )
                lines.append(f"- **{tr.test_id}** ({tr.name}): `{icon}` — {tr.notes or ''}")
        lines.append("")

        # Shares
        lines.append("## Share Access Summary")
        if context.shares:
            lines.append("| Share | Readable | Writable | Anonymous | Comment |")
            lines.append("|-------|----------|----------|-----------|---------|")
            for s in context.shares:
                lines.append(
                    f"| {s.name} | {s.readable} | {s.writable} | {s.anonymous_access} | {s.comment or ''} |"
                )
        else:
            lines.append("No shares enumerated.")
        lines.append("")

        # File findings
        lines.append("## Sensitive Files Found")
        high_risk = [f for f in context.file_findings if f.risk_score >= 7]
        if high_risk:
            lines.append("| Path | Share | Type | Risk Score | Rules |")
            lines.append("|------|-------|------|------------|-------|")
            for ff in high_risk:
                rules = ", ".join(ff.matched_rules)
                lines.append(f"| {ff.path} | {ff.share} | {ff.file_type} | {ff.risk_score} | {rules} |")
        else:
            lines.append("No high-risk files detected.")
        lines.append("")

        # Attack paths
        lines.append("## Attack Paths")
        if context.attack_paths:
            for ap in context.attack_paths:
                lines.append(f"### {ap.title}")
                lines.append(ap.description)
                lines.append(f"- **Confidence:** {ap.confidence}")
                lines.append(f"- **Impact:** {ap.impact}")
                if ap.next_steps:
                    lines.append("**Next Steps:**")
                    for step in ap.next_steps:
                        lines.append(f"  - {step}")
                lines.append("")
        else:
            lines.append("No attack paths identified.")
        lines.append("")

        # Errors
        if context.errors:
            lines.append("## Errors")
            for err in context.errors:
                lines.append(f"- {err}")
            lines.append("")

        out_path = context.output_base / "summaries" / "smb_summary.md"
        out_path.parent.mkdir(parents=True, exist_ok=True)
        out_path.write_text("\n".join(lines), encoding="utf-8")

    # ------------------------------------------------------------------
    # smb_controls.md
    # ------------------------------------------------------------------

    def _write_controls(self, context: ScanContext) -> None:
        lines: list[str] = []
        lines.append("# SMB Security Controls Assessment")
        lines.append("")

        passed = [c for c in context.control_assessments if c.status == ControlStatus.PASSED.value]
        failed = [c for c in context.control_assessments if c.status == ControlStatus.FAILED.value]
        inconclusive = [
            c for c in context.control_assessments
            if c.status in (ControlStatus.INCONCLUSIVE.value, ControlStatus.NOT_TESTED.value)
        ]

        lines.append("## Passed Controls")
        if passed:
            for c in passed:
                lines.append(f"### {c.control_id}: {c.name}")
                lines.append(f"- **Status:** PASSED")
                lines.append(f"- **Confidence:** {c.confidence}")
                lines.append(f"- **Reason:** {c.reason}")
                if c.evidence_ids:
                    lines.append(f"- **Evidence:** {', '.join(c.evidence_ids)}")
                lines.append("")
        else:
            lines.append("No controls passed.")
            lines.append("")

        lines.append("## Failed Controls")
        if failed:
            for c in failed:
                lines.append(f"### {c.control_id}: {c.name}")
                lines.append(f"- **Status:** FAILED")
                lines.append(f"- **Confidence:** {c.confidence}")
                lines.append(f"- **Reason:** {c.reason}")
                if c.evidence_ids:
                    lines.append(f"- **Evidence:** {', '.join(c.evidence_ids)}")
                lines.append("")
        else:
            lines.append("No controls failed.")
            lines.append("")

        lines.append("## Inconclusive / Not Tested")
        if inconclusive:
            for c in inconclusive:
                lines.append(f"### {c.control_id}: {c.name}")
                lines.append(f"- **Status:** {c.status.upper()}")
                lines.append(f"- **Reason:** {c.reason}")
                lines.append("")
        else:
            lines.append("All controls were tested.")
            lines.append("")

        # Test coverage summary
        lines.append("## Test Coverage")
        for tr in context.test_results:
            lines.append(f"- **{tr.test_id}** ({tr.name}): `{tr.status}` — confidence: {tr.confidence}")
        lines.append("")

        out_path = context.output_base / "summaries" / "smb_controls.md"
        out_path.parent.mkdir(parents=True, exist_ok=True)
        out_path.write_text("\n".join(lines), encoding="utf-8")
