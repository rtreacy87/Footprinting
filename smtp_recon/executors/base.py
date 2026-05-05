from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any


@dataclass
class ExecutionResult:
    stdout: str
    stderr: str
    return_code: int
    elapsed_seconds: float = 0.0
    extra: dict[str, Any] = field(default_factory=dict)

    @property
    def succeeded(self) -> bool:
        return self.return_code == 0
