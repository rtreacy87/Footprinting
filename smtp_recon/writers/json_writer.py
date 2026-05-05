from __future__ import annotations

import dataclasses
import json
import logging
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from ..models.result import CheckResult
from ..models.scan_context import ScanContext

logger = logging.getLogger(__name__)


def _serialize(obj: Any) -> Any:
    """Recursively serialize objects for JSON output."""
    if dataclasses.is_dataclass(obj) and not isinstance(obj, type):
        return dataclasses.asdict(obj)
    if isinstance(obj, Path):
        return str(obj)
    if isinstance(obj, (list, tuple)):
        return [_serialize(i) for i in obj]
    if isinstance(obj, dict):
        return {k: _serialize(v) for k, v in obj.items()}
    return obj


class JsonWriter:
    """Write CheckResult lists and summary dicts to JSON files."""

    def write_results(
        self,
        context: ScanContext,
        results: list[CheckResult],
        extra: dict[str, Any] | None = None,
    ) -> Path:
        out_dir = context.target_dir / "findings"
        out_dir.mkdir(parents=True, exist_ok=True)
        out_path = out_dir / "results.json"

        payload: dict[str, Any] = {
            "target": context.target.ip,
            "domain": context.target.domain,
            "scanned_at": datetime.now(timezone.utc).isoformat(),
            "open_ports": context.open_ports,
            "safe_mode": context.safe_mode,
            "results": [_serialize(r) for r in results],
        }
        if extra:
            payload.update({k: _serialize(v) for k, v in extra.items()})

        out_path.write_text(json.dumps(payload, indent=2), encoding="utf-8")
        logger.info("[json_writer] Wrote results to %s", out_path)
        return out_path

    def write_dict(self, path: Path, data: dict | list) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(_serialize(data), indent=2), encoding="utf-8")
        logger.debug("[json_writer] Wrote %s", path)
