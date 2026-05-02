from __future__ import annotations
from abc import ABC, abstractmethod

from ..config import ScanContext
from ..core.result import CheckResult


class BaseCheck(ABC):
    name: str = ""
    required_tools: list[str] = []

    def can_run(self, context: ScanContext) -> bool:
        for tool in self.required_tools:
            if not context.tool_status.get(tool, False):
                return False
        return True

    @abstractmethod
    def run(self, context: ScanContext) -> CheckResult:
        raise NotImplementedError
