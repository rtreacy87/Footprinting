from __future__ import annotations
from dataclasses import dataclass, field
from datetime import datetime


@dataclass
class CommandResult:
    tool_name: str
    command: list[str]
    started_at: str
    completed_at: str
    return_code: int
    stdout: str
    stderr: str
    raw_output_path: str | None = None

    @property
    def output(self) -> str:
        return self.stdout + self.stderr

    @property
    def succeeded(self) -> bool:
        return self.return_code == 0


@dataclass
class CheckResult:
    check_name: str
    status: str  # "ok" | "skipped" | "error" | "no_result"
    raw_artifacts: list = field(default_factory=list)
    parsed_artifacts: list = field(default_factory=list)
    findings: list = field(default_factory=list)
    notes: list[str] = field(default_factory=list)
