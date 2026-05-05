from __future__ import annotations

from abc import ABC, abstractmethod

from ..models.result import CheckResult
from ..models.scan_context import ScanContext


class BaseCheck(ABC):
    name: str = "base"

    @abstractmethod
    def run(self, context: ScanContext) -> CheckResult:
        ...

    def _skipped(self, target: str, reason: str) -> CheckResult:
        return CheckResult(
            name=self.name,
            target=target,
            port=0,
            status="skipped",
            summary=reason,
        )
