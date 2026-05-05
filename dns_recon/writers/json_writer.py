from __future__ import annotations

import json
from pathlib import Path


class JsonWriter:
    def __init__(self, output_root: Path) -> None:
        self._root = output_root

    def write(self, category: str, filename: str, data: object) -> Path:
        dest = self._root / category / filename
        dest.parent.mkdir(parents=True, exist_ok=True)
        dest.write_text(json.dumps(data, indent=2, default=str), encoding="utf-8")
        return dest

    def write_records(self, record_type: str, records: list[dict]) -> Path:
        return self.write("parsed/records", f"{record_type}.json", records)

    def write_attempts(self, category: str, attempts: list[dict]) -> Path:
        return self.write(f"attempts/{category}", "attempts.json", attempts)

    def write_analysis(self, filename: str, data: object) -> Path:
        return self.write("analysis", filename, data)

    def write_pivots(self, pivot_type: str, data: list[dict]) -> Path:
        return self.write("pivots", f"{pivot_type}_targets.json", data)

    def write_metadata(self, filename: str, data: object) -> Path:
        return self.write("metadata", filename, data)

    def write_subdomains(self, category: str, data: list[dict]) -> Path:
        return self.write("parsed/subdomains", f"{category}.json", data)
