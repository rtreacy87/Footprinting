from __future__ import annotations


class SmbEnumError(Exception):
    """Base exception for all smb_enum errors."""


class ToolNotFoundError(SmbEnumError):
    def __init__(self, tool: str) -> None:
        super().__init__(f"Required tool not found on PATH: {tool}")
        self.tool = tool


class CommandTimeoutError(SmbEnumError):
    def __init__(self, tool: str, timeout: int) -> None:
        super().__init__(f"{tool} timed out after {timeout}s")
        self.tool = tool
        self.timeout = timeout


class ParseError(SmbEnumError):
    def __init__(self, parser: str, detail: str) -> None:
        super().__init__(f"Parser '{parser}' failed: {detail}")
        self.parser = parser


class EvidenceNotFoundError(SmbEnumError):
    def __init__(self, evidence_id: str) -> None:
        super().__init__(f"Evidence not found: {evidence_id}")
        self.evidence_id = evidence_id


class InconclusiveTestError(SmbEnumError):
    def __init__(self, test_id: str, reason: str) -> None:
        super().__init__(f"Test {test_id} was inconclusive: {reason}")
        self.test_id = test_id
        self.reason = reason
