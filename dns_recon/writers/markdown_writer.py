from __future__ import annotations

from pathlib import Path


class MarkdownWriter:
    def __init__(self, output_root: Path) -> None:
        self._root = output_root

    def write(self, filename: str, content: str) -> Path:
        dest = self._root / "summary" / filename
        dest.parent.mkdir(parents=True, exist_ok=True)
        dest.write_text(content, encoding="utf-8")
        return dest
