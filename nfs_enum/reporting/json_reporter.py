from __future__ import annotations

import dataclasses
import json
from pathlib import Path

from ..context import ScanContext


def _to_dict(obj):
    if dataclasses.is_dataclass(obj):
        return {k: _to_dict(v) for k, v in dataclasses.asdict(obj).items()}
    if isinstance(obj, list):
        return [_to_dict(i) for i in obj]
    return obj


class JsonReporter:
    def write(self, context: ScanContext) -> Path:
        report = context.to_report()
        data = _to_dict(report)

        attack_paths = {
            "direct_access": context.direct_access,
            "pivot_required": not context.direct_access and context.nfs_detected,
        }
        context.path("summary", "attack_paths.json").write_text(
            json.dumps(attack_paths, indent=2), encoding="utf-8"
        )

        tests_performed = ["nmap", "rpcinfo", "showmount"]
        tests_successful = ["nmap"] if context.nfs_detected else []
        if context.enumeration and context.enumeration.exports:
            tests_successful.append("showmount")
        tests_failed = [
            t for t in tests_performed if t not in tests_successful
        ]
        mount_versions = [a.nfs_version for a in context.mount_attempts]
        tests_performed += [f"mount_v{v}" for v in mount_versions]
        tests_failed += [f"mount_v{a.nfs_version}" for a in context.mount_attempts if not a.success]
        tests_successful += [f"mount_v{a.nfs_version}" for a in context.mount_attempts if a.success]

        coverage = {
            "tests_performed": tests_performed,
            "tests_successful": tests_successful,
            "tests_failed": tests_failed,
        }
        context.path("summary", "test_coverage.json").write_text(
            json.dumps(coverage, indent=2), encoding="utf-8"
        )

        out_path = context.path("summary", "report.json")
        out_path.write_text(json.dumps(data, indent=2), encoding="utf-8")
        return out_path
