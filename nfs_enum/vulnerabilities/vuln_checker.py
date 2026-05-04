from __future__ import annotations

import json

from ..context import ScanContext
from ..models import Vulnerability


class VulnChecker:
    def run(self, context: ScanContext) -> None:
        vulns: list[Vulnerability] = []

        # World-accessible exports
        for export in context.exports:
            if export.allowed_hosts in ("*", "everyone", ""):
                vulns.append(Vulnerability(
                    vuln_type="world_accessible_export",
                    severity="high",
                    description=f"Export {export.path} is accessible to all hosts ({export.allowed_hosts})",
                    exploitable=True,
                    requires_pivot=False,
                    evidence=f"showmount -e: {export.path} {export.allowed_hosts}",
                ))

        # No root_squash
        for perm in context.permissions:
            if not perm.root_squash_enabled:
                vulns.append(Vulnerability(
                    vuln_type="no_root_squash",
                    severity="critical",
                    description=f"no_root_squash on {perm.export_path} allows root privilege escalation",
                    exploitable=True,
                    requires_pivot=not context.direct_access,
                    evidence=perm.uid_gid_notes,
                ))

        # Writable shares
        for perm in context.permissions:
            if perm.writable:
                vulns.append(Vulnerability(
                    vuln_type="writable_export",
                    severity="high",
                    description=f"Export {perm.export_path} is writable",
                    exploitable=True,
                    requires_pivot=not context.direct_access,
                ))

        context.vulnerabilities = vulns

        issues = [
            {
                "type": v.vuln_type,
                "severity": v.severity,
                "exploitable": v.exploitable,
                "requires_pivot": v.requires_pivot,
                "description": v.description,
            }
            for v in vulns
        ]
        context.path("vulnerabilities", "findings.json").write_text(
            json.dumps({"issues": issues}, indent=2), encoding="utf-8"
        )
        context.path("vulnerabilities", "misconfigurations.json").write_text(
            json.dumps(
                {"misconfigurations": [i for i in issues if not i["exploitable"]]},
                indent=2,
            ),
            encoding="utf-8",
        )
