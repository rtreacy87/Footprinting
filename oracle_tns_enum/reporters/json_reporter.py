from __future__ import annotations
import json
from pathlib import Path

from ..config import ScanContext


class JsonReporter:
    def write(self, context: ScanContext) -> None:
        out = context.config.output_base / context.target_host
        out.mkdir(parents=True, exist_ok=True)

        metadata = {
            "target": context.target_host,
            "port": context.target_port,
            "oracle_detected": context.tool_status.get("oracle_detected"),
            "sids": context.discovered_sids,
            "service_names": context.discovered_service_names,
            "valid_credentials": [c.model_dump() for c in context.valid_credentials],
            "decision_trace": context.decision_trace,
        }
        (out / "scan_metadata.json").write_text(
            json.dumps(metadata, indent=2, default=str), encoding="utf-8"
        )

        parsed = out / "parsed"
        parsed.mkdir(parents=True, exist_ok=True)

        (parsed / "findings.json").write_text(
            json.dumps(
                [f.model_dump() for f in context.findings],
                indent=2,
                default=str,
            ),
            encoding="utf-8",
        )

        (parsed / "sids.json").write_text(
            json.dumps({"sids": context.discovered_sids}, indent=2),
            encoding="utf-8",
        )

        (parsed / "credentials.json").write_text(
            json.dumps(
                [c.model_dump() for c in context.valid_credentials],
                indent=2,
                default=str,
            ),
            encoding="utf-8",
        )
