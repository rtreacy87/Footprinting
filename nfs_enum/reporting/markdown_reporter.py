from __future__ import annotations

from pathlib import Path

from ..context import ScanContext


class MarkdownReporter:
    def write(self, context: ScanContext) -> Path:
        lines: list[str] = []
        lines.append(f"# NFS Recon — {context.target}\n")

        lines.append("## Discovery\n")
        if context.discovery:
            d = context.discovery
            lines.append(f"- Port 111: {'open' if d.port_111_open else 'closed'}")
            lines.append(f"- Port 2049: {'open' if d.port_2049_open else 'closed'}")
            lines.append(f"- NFS detected: {d.nfs_detected}")
            if d.rpc_services:
                lines.append(f"- RPC services: {len(d.rpc_services)} found")
        lines.append("")

        lines.append("## Exports\n")
        if context.enumeration and context.enumeration.exports:
            for e in context.enumeration.exports:
                lines.append(f"- `{e.path}` — allowed: `{e.allowed_hosts}`")
        else:
            lines.append("- No exports found")
        lines.append("")

        lines.append("## Mount Attempts\n")
        if context.mount_attempts:
            for a in context.mount_attempts:
                status = "SUCCESS" if a.success else f"FAILED ({a.failure_type or 'unknown'})"
                lines.append(f"- Attempt {a.attempt_number}: `{a.export_path}` NFSv{a.nfs_version} — {status}")
        else:
            lines.append("- No mount attempts made")
        lines.append("")

        lines.append("## Vulnerabilities\n")
        if context.vulnerabilities:
            for v in context.vulnerabilities:
                lines.append(f"- **{v.severity.upper()}** `{v.vuln_type}`: {v.description}")
        else:
            lines.append("- No vulnerabilities identified")
        lines.append("")

        lines.append("## Attack Paths\n")
        lines.append(f"- Direct access: {context.direct_access}")
        lines.append(f"- Pivot required: {not context.direct_access and context.nfs_detected}")
        lines.append("")

        if context.errors:
            lines.append("## Errors\n")
            for err in context.errors:
                lines.append(f"- {err}")
            lines.append("")

        out_path = context.path("summary", "findings.md")
        out_path.write_text("\n".join(lines), encoding="utf-8")
        return out_path
