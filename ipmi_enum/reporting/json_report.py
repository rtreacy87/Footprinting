from __future__ import annotations

import dataclasses
import json
from pathlib import Path

from ..context import ScanContext


class JsonReporter:
    def write(self, context: ScanContext, output_path: Path | None = None) -> Path:
        path = output_path or (context.output_dir / "findings.json")

        report = context.to_report()

        def _serialize(obj):
            if dataclasses.is_dataclass(obj):
                return dataclasses.asdict(obj)
            raise TypeError(f"Cannot serialize {type(obj)}")

        path.write_text(json.dumps(dataclasses.asdict(report), indent=2, default=str), encoding="utf-8")
        return path
