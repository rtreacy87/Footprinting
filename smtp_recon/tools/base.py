from __future__ import annotations

from abc import ABC, abstractmethod
from pathlib import Path

from ..executors.subprocess_executor import SubprocessExecutor


class BaseTool(ABC):
    def __init__(self, executor: SubprocessExecutor | None = None, timeout: int = 120) -> None:
        self._executor = executor or SubprocessExecutor(timeout=timeout)

    @property
    @abstractmethod
    def tool_name(self) -> str:
        ...

    def _save(self, path: Path, content: str) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content, encoding="utf-8")
