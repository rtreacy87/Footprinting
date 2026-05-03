from __future__ import annotations

import dataclasses
import json
from pathlib import Path
from typing import Any

from ..context import ScanContext
from .report_registry import register_reporter
from .reporter import Reporter


def _to_dict(obj: Any) -> Any:
    """Recursively convert dataclasses and collections to JSON-serializable types."""
    if dataclasses.is_dataclass(obj) and not isinstance(obj, type):
        return {k: _to_dict(v) for k, v in dataclasses.asdict(obj).items()}
    if isinstance(obj, list):
        return [_to_dict(i) for i in obj]
    if isinstance(obj, dict):
        # Handle tuple keys (like file_contents: dict[tuple[str,str], str])
        result = {}
        for k, v in obj.items():
            key = str(k) if isinstance(k, tuple) else k
            result[key] = _to_dict(v)
        return result
    return obj


def _write_json(path: Path, data: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, indent=2, default=str), encoding="utf-8")


@register_reporter("json")
class JsonReporter(Reporter):
    """Writes structured JSON reports."""

    def write(self, context: ScanContext) -> None:
        base = context.output_base

        # smb_findings.json — all findings structured
        findings = {
            "target": context.target,
            "profile": context.config.profile.value,
            "shares": _to_dict(context.shares),
            "users": _to_dict(context.users),
            "groups": _to_dict(context.groups),
            "file_findings": _to_dict(context.file_findings),
            "protocol_info": _to_dict(context.protocol_info) if context.protocol_info else None,
            "attack_paths": _to_dict(context.attack_paths),
            "blocked_paths": _to_dict(context.blocked_paths),
            "domain": context.domain,
            "smb_version_banner": context.smb_version_banner,
            "errors": context.errors,
        }
        _write_json(base / "summaries" / "smb_findings.json", findings)

        # smb_risk_scores.json
        risk_scores = [
            {
                "path": ff.path,
                "share": ff.share,
                "file_type": ff.file_type,
                "risk_score": ff.risk_score,
                "matched_rules": ff.matched_rules,
            }
            for ff in context.file_findings
        ]
        _write_json(base / "summaries" / "smb_risk_scores.json", risk_scores)

        # tests/test_results.json
        _write_json(
            base / "tests" / "test_results.json",
            _to_dict(context.test_results),
        )

        # validation/validation_summary.json
        validation = {
            "control_assessments": _to_dict(context.control_assessments),
            "tests_run": len(context.test_results),
            "skipped_steps": context.skipped_steps,
        }
        _write_json(base / "validation" / "validation_summary.json", validation)

        # attack_paths/candidate_paths.json
        _write_json(
            base / "attack_paths" / "candidate_paths.json",
            _to_dict(context.attack_paths),
        )

        # attack_paths/blocked_paths.json
        _write_json(
            base / "attack_paths" / "blocked_paths.json",
            _to_dict(context.blocked_paths),
        )

        # shares/share_list.json
        _write_json(
            base / "shares" / "share_list.json",
            _to_dict(context.shares),
        )

        # users/users.json
        _write_json(base / "users" / "users.json", _to_dict(context.users))
        _write_json(base / "users" / "groups.json", _to_dict(context.groups))

        # metadata/smb_version.json
        if context.protocol_info:
            _write_json(
                base / "metadata" / "smb_version.json",
                _to_dict(context.protocol_info),
            )

        # security/smb_signing.json
        if context.protocol_info:
            signing_info = {
                "signing_enabled": context.protocol_info.signing_enabled,
                "signing_required": context.protocol_info.signing_required,
            }
            _write_json(base / "security" / "smb_signing.json", signing_info)
            smb1_info = {"smb1_enabled": context.protocol_info.smb1_enabled}
            _write_json(base / "security" / "smb_protocols.json", smb1_info)
