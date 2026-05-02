from __future__ import annotations

from pathlib import Path


class OutputPaths:
    def __init__(self, base: Path, target_id: str) -> None:
        self.root = base / target_id
        self.raw = self.root / "raw"
        self.parsed = self.root / "parsed"
        self.hashes = self.root / "hashes"
        self.markdown = self.root / "markdown"

    def setup(self) -> None:
        for d in (self.raw, self.parsed, self.hashes, self.markdown):
            d.mkdir(parents=True, exist_ok=True)
