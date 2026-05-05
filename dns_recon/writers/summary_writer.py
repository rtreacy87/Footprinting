from __future__ import annotations

import json
from pathlib import Path


class SummaryWriter:
    def __init__(self, output_root: Path) -> None:
        self._root = output_root

    def write_quick_view(self, data: dict) -> Path:
        dest = self._root / "summary" / "quick_view.json"
        dest.parent.mkdir(parents=True, exist_ok=True)
        dest.write_text(json.dumps(data, indent=2, default=str), encoding="utf-8")
        return dest
