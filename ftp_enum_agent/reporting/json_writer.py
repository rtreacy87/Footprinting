from __future__ import annotations

import dataclasses
import json
from pathlib import Path

from ..models import ScanReport


class JsonWriter:
    def write(self, report: ScanReport, output_dir: Path) -> Path:
        output_dir.mkdir(parents=True, exist_ok=True)

        def _default(obj):
            if dataclasses.is_dataclass(obj):
                return dataclasses.asdict(obj)
            return str(obj)

        # Full findings
        findings_path = output_dir / "findings.json"
        findings_path.write_text(
            json.dumps([dataclasses.asdict(f) for f in report.findings], indent=2, default=str),
            encoding="utf-8",
        )

        # Summary / agent-facing decision
        summary = {
            "target": f"{report.target.host}:{report.target.port}",
            "ftp_is_useful_path": any(f.is_attack_path for f in report.findings),
            "best_attack_path": next(
                (f.attack_path_type for f in report.findings if f.is_attack_path), "none"
            ),
            "highest_severity": report.highest_severity(),
            "confidence": next(
                (f.confidence for f in report.findings if f.is_attack_path), "low"
            ),
            "anonymous_login": report.anonymous_login_success,
            "listing_allowed": report.listing_allowed,
            "download_allowed": report.download_allowed,
            "upload_allowed": report.upload_allowed,
            "credentials_or_configs_found": report.credentials_or_configs_found,
            "next_steps": next(
                (f.recommended_next_steps for f in report.findings if f.is_attack_path), []
            ),
        }
        summary_path = output_dir / "summary.json"
        summary_path.write_text(json.dumps(summary, indent=2), encoding="utf-8")

        # File inventory
        inventory_path = output_dir / "file_inventory.json"
        inventory_path.write_text(
            json.dumps([dataclasses.asdict(e) for e in report.file_inventory], indent=2, default=str),
            encoding="utf-8",
        )

        # Credential candidates (with raw values for raw output, redacted in the report field)
        creds_path = output_dir / "credential_candidates.json"
        creds_path.write_text(
            json.dumps([dataclasses.asdict(c) for c in report.credential_candidates], indent=2, default=str),
            encoding="utf-8",
        )

        return findings_path
