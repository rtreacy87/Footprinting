from __future__ import annotations

import json
import re
import subprocess
import tempfile
from pathlib import Path

from ..context import ScanContext
from ..models import PermissionResult


class PermissionAnalyzer:
    def run(self, context: ScanContext) -> None:
        results: list[PermissionResult] = []

        for export in context.exports:
            perm = self._analyze_export(context, export.path)
            results.append(perm)

        context.permissions = results

        serialized = [
            {
                "export_path": p.export_path,
                "writable": p.writable,
                "root_squash_enabled": p.root_squash_enabled,
                "uid_gid_notes": p.uid_gid_notes,
                "risk": p.risk,
            }
            for p in results
        ]

        context.path("permissions", "permissions_raw.txt").write_text(
            "\n".join(f"{p.export_path}: risk={p.risk}" for p in results), encoding="utf-8"
        )
        context.path("permissions", "write_access.json").write_text(
            json.dumps({"writable_exports": [p.export_path for p in results if p.writable]}, indent=2),
            encoding="utf-8",
        )
        context.path("permissions", "root_squash_check.json").write_text(
            json.dumps(
                {
                    "exports": [
                        {
                            "path": p.export_path,
                            "writable": p.writable,
                            "root_squash": p.root_squash_enabled,
                            "risk": p.risk,
                        }
                        for p in results
                    ]
                },
                indent=2,
            ),
            encoding="utf-8",
        )
        context.path("permissions", "uid_gid_map.json").write_text(
            json.dumps({"notes": [p.uid_gid_notes for p in results if p.uid_gid_notes]}, indent=2),
            encoding="utf-8",
        )

    def _analyze_export(self, context: ScanContext, export_path: str) -> PermissionResult:
        perm = PermissionResult(export_path=export_path)

        # Check /etc/exports style hints in showmount output (no_root_squash detection)
        showmount_raw = ""
        if context.enumeration:
            showmount_raw = context.enumeration.showmount_raw + context.enumeration.nfs_scripts_raw

        if "no_root_squash" in showmount_raw.lower():
            perm.root_squash_enabled = False
            perm.risk = "critical"
        elif "no_all_squash" in showmount_raw.lower():
            perm.root_squash_enabled = False
            perm.risk = "high"

        if not perm.root_squash_enabled:
            perm.risk = "critical" if not perm.root_squash_enabled else "high"

        return perm
