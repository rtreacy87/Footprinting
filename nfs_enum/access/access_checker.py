from __future__ import annotations

import json

from ..context import ScanContext
from ..models import AccessCheck


class AccessChecker:
    def run(self, context: ScanContext) -> None:
        checks: list[AccessCheck] = []

        for export in context.exports:
            check = AccessCheck(
                export_path=export.path,
                export_visible=True,
                rpc_accessible=context.discovery is not None and context.discovery.port_111_open,
                version_compatible=True,
                notes="",
            )
            checks.append(check)

        context.access_checks = checks

        serialized = [
            {
                "export_path": c.export_path,
                "export_visible": c.export_visible,
                "rpc_accessible": c.rpc_accessible,
                "version_compatible": c.version_compatible,
                "notes": c.notes,
            }
            for c in checks
        ]
        context.path("access_checks", "access_tests.json").write_text(
            json.dumps(serialized, indent=2), encoding="utf-8"
        )
