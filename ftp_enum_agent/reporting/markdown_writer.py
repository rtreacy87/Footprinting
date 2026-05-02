from __future__ import annotations

from pathlib import Path

from ..models import ScanReport


class MarkdownWriter:
    def write(self, report: ScanReport, output_dir: Path) -> Path:
        output_dir.mkdir(parents=True, exist_ok=True)
        path = output_dir / "summary.md"
        path.write_text(self._build(report), encoding="utf-8")
        return path

    def _build(self, report: ScanReport) -> str:
        t = report.target
        lines = [
            f"# FTP Enumeration Summary: {t.host}:{t.port}",
            "",
            "## Executive Summary",
            "",
        ]

        attack_paths = [f for f in report.findings if f.is_attack_path]
        if attack_paths:
            lines.append(
                f"FTP at {t.host}:{t.port} represents a viable attack path. "
                f"Highest severity: **{report.highest_severity()}**. "
                f"{len(attack_paths)} attack path(s) identified."
            )
        else:
            lines.append(f"FTP at {t.host}:{t.port} does not currently provide a useful attack path.")
        lines.append("")

        # Target info
        lines += [
            "## Target Information",
            "",
            "| Field | Value |",
            "|---|---|",
            f"| Host | {t.host} |",
            f"| Port | {t.port} |",
            f"| Protocol | {t.protocol.upper()} |",
            f"| Scan Started | {t.scan_started_at} |",
            f"| Scan Completed | {t.scan_completed_at or 'N/A'} |",
            "",
        ]

        # Required checks table
        lines += [
            "## Required Checks",
            "",
            "| Check | Result | Attack Path? | Severity | Evidence |",
            "|---|---|---|---|---|",
        ]
        check_display = [
            ("anonymous_login", "Anonymous login"),
            ("directory_listing", "Enumerate everything"),
            ("download", "Download everything accessible"),
            ("secret_scan", "Credentials/configs review"),
            ("upload", "Upload capability"),
        ]
        for check_name, display_name in check_display:
            r = report.result(check_name)
            result_str = r.summary[:60] if r else "Not tested"
            status = r.status if r else "not_tested"
            relevant = next((f for f in report.findings if check_name in " ".join(f.evidence_ids)), None)
            ap = "Yes" if (relevant and relevant.is_attack_path) else "No"
            sev = relevant.severity if relevant else "info"
            ev = ", ".join(r.evidence_ids) if r else "—"
            lines.append(f"| {display_name} | {status} | {ap} | {sev} | {ev} |")
        lines.append("")

        # Attack paths
        if report.findings:
            lines += ["## Attack Path Assessment", ""]
            for f in report.findings:
                lines += [
                    f"### {f.title}",
                    "",
                    f"- **Severity:** {f.severity}",
                    f"- **Confidence:** {f.confidence}",
                    f"- **Attack Path:** {'Yes' if f.is_attack_path else 'No'}",
                    f"- **Type:** {f.attack_path_type}",
                    f"- **Evidence:** {', '.join(f.evidence_ids) or '—'}",
                    "",
                    f.description,
                    "",
                ]
                if f.recommended_next_steps:
                    lines.append("**Recommended Next Steps:**")
                    for step in f.recommended_next_steps:
                        lines.append(f"- {step}")
                    lines.append("")

        # File inventory highlights
        interesting = [e for e in report.file_inventory if not e.is_dir][:20]
        if interesting:
            lines += [
                "## File Inventory Highlights",
                "",
                "| Path | Size | Type |",
                "|---|---|---|",
            ]
            for e in interesting:
                size = f"{e.size} B" if e.size is not None else "?"
                ftype = "dir" if e.is_dir else "file"
                lines.append(f"| `{e.path}` | {size} | {ftype} |")
            lines.append("")

        # Credential candidates (redacted)
        if report.credential_candidates:
            lines += [
                "## Credential and Configuration Candidates",
                "",
                "| File | Type | Confidence | Redacted Value |",
                "|---|---|---|---|",
            ]
            for c in report.credential_candidates:
                fname = Path(c.file_path).name
                lines.append(f"| `{fname}` | {c.match_type} | {c.confidence} | `{c.redacted_value}` |")
            lines.append("")

        # Evidence index
        if report.evidence:
            lines += [
                "## Evidence Index",
                "",
                "| Evidence ID | Collector | Raw Output Path | SHA256 |",
                "|---|---|---|---|",
            ]
            for ev in report.evidence:
                sha = (ev.sha256 or "")[:16] + "..."
                lines.append(f"| {ev.evidence_id} | {ev.collector} | `{ev.raw_output_path or '—'}` | `{sha}` |")
            lines.append("")

        return "\n".join(lines)
