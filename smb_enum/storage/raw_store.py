from __future__ import annotations

from pathlib import Path


class RawStore:
    """Saves raw command output to disk."""

    def __init__(self, base: Path) -> None:
        self._base = Path(base)

    def save_stdout(self, tool: str, name: str, content: str) -> Path:
        """Save content to raw/<tool>/<name> and return the path."""
        path = self._base / "raw" / tool / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content, encoding="utf-8")
        return path

    def save_stderr(self, tool: str, name: str, content: str) -> Path:
        """Save stderr content to raw/<tool>/<name>.err and return the path."""
        path = self._base / "raw" / tool / f"{name}.err"
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content, encoding="utf-8")
        return path
