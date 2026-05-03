from __future__ import annotations

import uuid
from abc import ABC, abstractmethod

from ..context import ScanContext
from ..core.enums import TestStatus, Confidence
from ..models import TestResult


class BaseTest(ABC):
    """Abstract base class for all SMB test specifications."""

    test_id: str = ""
    name: str = ""
    category: str = ""
    tool: str = ""
    expected_secure_result: str = ""

    @abstractmethod
    def run(self, context: ScanContext) -> TestResult:
        """Execute the test and return a structured result."""
        ...

    def _make_inconclusive_result(
        self,
        reason: str,
        evidence_ids: list[str] | None = None,
        command: str = "",
    ) -> TestResult:
        """Helper to build an inconclusive TestResult."""
        return TestResult(
            test_id=self.test_id,
            name=self.name,
            category=self.category,
            tool=self.tool,
            command=command,
            status=TestStatus.INCONCLUSIVE.value,
            evidence_ids=evidence_ids or [],
            confidence=Confidence.UNKNOWN.value,
            notes=reason,
            expected_secure_result=self.expected_secure_result,
            actual_result=None,
        )

    def _make_error_result(
        self,
        reason: str,
        evidence_ids: list[str] | None = None,
        command: str = "",
    ) -> TestResult:
        """Helper to build an error TestResult."""
        return TestResult(
            test_id=self.test_id,
            name=self.name,
            category=self.category,
            tool=self.tool,
            command=command,
            status=TestStatus.ERROR.value,
            evidence_ids=evidence_ids or [],
            confidence=Confidence.UNKNOWN.value,
            notes=reason,
            expected_secure_result=self.expected_secure_result,
            actual_result=None,
        )
