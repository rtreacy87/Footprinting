from __future__ import annotations

from pathlib import Path

from ..context import ScanContext
from ..core.redaction import Redactor


class MarkdownReporter:
    def __init__(self, redact: bool = True) -> None:
        self._redactor = Redactor(redact_passwords=redact, redact_hashes=redact)

    def write(self, context: ScanContext, output_path: Path | None = None) -> Path:
        path = output_path or (context.output_dir / "report.md")
        path.write_text(self._build(context), encoding="utf-8")
        return path

    def _build(self, context: ScanContext) -> str:
        lines = [
            f"# IPMI Enumeration Report: {context.target}",
            f"\n**Profile:** {context.profile.value}",
            "",
        ]

        # Executive Summary
        lines += ["## Executive Summary", ""]
        if context.ipmi_finding and context.ipmi_finding.ipmi_detected:
            lines.append(f"IPMI detected on {context.target}:623 (UDP). "
                         f"Version: {context.ipmi_finding.protocol_version or 'unknown'}.")
        else:
            lines.append("IPMI not detected on this target.")

        if context.credentials:
            cracked = [c for c in context.credentials if c.status == "cracked"]
            valid = [c for c in context.credentials if c.status == "valid"]
            if cracked:
                lines.append(f"\n**{len(cracked)} credential(s) cracked:** " +
                             ", ".join(c.username for c in cracked))
            elif valid:
                lines.append(f"\n**{len(valid)} valid credential(s) found.**")
        lines.append("")

        # IPMI Fingerprint
        lines += ["## IPMI Fingerprint", ""]
        if context.ipmi_finding:
            f = context.ipmi_finding
            lines += [
                f"- **Detected:** {f.ipmi_detected}",
                f"- **Port:** {f.port}/UDP",
                f"- **Version:** {f.protocol_version or 'N/A'}",
                f"- **UserAuth:** {', '.join(f.user_auth) or 'N/A'}",
                f"- **PassAuth:** {', '.join(f.pass_auth) or 'N/A'}",
                f"- **Privilege Level:** {f.privilege_level or 'N/A'}",
                f"- **Vendor Hint:** {f.vendor or 'N/A'}",
                "",
            ]

        # Companion Services
        if context.companion_services:
            lines += ["## Companion Management Interfaces", ""]
            for svc in context.companion_services:
                lines.append(f"- TCP/{svc.port} {svc.service} ({svc.state})"
                             + (f" — {svc.banner}" if svc.banner else ""))
            lines.append("")

        # Hashes
        if context.hashes:
            lines += ["## RAKP Hash Retrieval", ""]
            for h in context.hashes:
                lines.append(f"- **{h.username}**: hash retrieved")
                if h.cracked_password:
                    lines.append(f"  - Password cracked: `[REDACTED]`")
            lines.append("")

        # Credentials
        if context.credentials:
            lines += ["## Credential Findings", ""]
            for cred in context.credentials:
                if cred.status == "cracked":
                    lines.append(f"- **{cred.username}** — cracked via {cred.source}")
                elif cred.status == "valid":
                    lines.append(f"- **{cred.username}** — valid credential ({cred.source})")
                elif cred.status == "hash_only":
                    lines.append(f"- **{cred.username}** — hash retrieved, not cracked")
            lines.append("")

        # Findings
        if context.risk_findings:
            lines += ["## Findings and Risk", ""]
            for rf in context.risk_findings:
                lines += [
                    f"### [{rf.severity.upper()}] {rf.title}",
                    "",
                    rf.description,
                    "",
                ]
                if rf.remediation:
                    lines += [f"**Remediation:** {rf.remediation}", ""]

        # Evidence
        if context.evidence_refs:
            lines += ["## Raw Evidence Index", ""]
            for ref in context.evidence_refs:
                lines.append(f"- `{ref}`")
            lines.append("")

        # Errors/Skipped
        if context.errors or context.skipped_steps:
            lines += ["## Scan Notes", ""]
            for err in context.errors:
                lines.append(f"- **Error:** {err}")
            for skip in context.skipped_steps:
                lines.append(f"- **Skipped** `{skip['step']}`: {skip['reason']}")
            lines.append("")

        return "\n".join(lines)
