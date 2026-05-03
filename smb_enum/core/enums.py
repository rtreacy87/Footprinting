from __future__ import annotations

from enum import Enum


class ControlStatus(str, Enum):
    PASSED = "passed"
    FAILED = "failed"
    INCONCLUSIVE = "inconclusive"
    NOT_TESTED = "not_tested"


class TestStatus(str, Enum):
    PASSED_VULNERABLE = "passed_vulnerable"
    FAILED_SECURE = "failed_secure"
    INCONCLUSIVE = "inconclusive"
    ERROR = "error"
    NOT_RUN = "not_run"


class Confidence(str, Enum):
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    UNKNOWN = "unknown"


class RiskLevel(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"
