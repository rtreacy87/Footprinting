from __future__ import annotations

from pathlib import Path


class RawWriter:
    def __init__(self, output_root: Path) -> None:
        self._root = output_root

    def write(self, category: str, filename: str, content: str) -> Path:
        dest = self._root / "raw" / category / filename
        dest.parent.mkdir(parents=True, exist_ok=True)
        dest.write_text(content, encoding="utf-8")
        return dest

    def write_dig(self, record_type: str, content: str) -> Path:
        return self.write("dig", f"{record_type}.txt", content)

    def write_zone_transfer(self, nameserver: str, content: str) -> Path:
        safe_ns = nameserver.replace(".", "_").replace("@", "")
        return self.write("zone_transfer", f"axfr_{safe_ns}.txt", content)

    def write_tool(self, tool: str, filename: str, content: str) -> Path:
        return self.write(tool, filename, content)
