from __future__ import annotations
import json
from pathlib import Path


class OutputPaths:
    def __init__(self, base_dir: Path, target_host: str) -> None:
        self._root = base_dir / target_host
        self.raw = self._root / "raw"
        self.parsed = self._root / "parsed"
        self.reports = self._root / "reports"
        self.logs = self._root / "logs"

    def setup(self) -> None:
        for d in [self.raw, self.parsed, self.reports, self.logs]:
            d.mkdir(parents=True, exist_ok=True)

    def raw_file(self, name: str) -> Path:
        return self.raw / name

    def parsed_file(self, name: str) -> Path:
        return self.parsed / name

    def report_file(self, name: str) -> Path:
        return self.reports / name

    def save_json(self, name: str, data: dict) -> Path:
        path = self.parsed_file(name)
        path.write_text(json.dumps(data, indent=2, default=str), encoding="utf-8")
        return path
