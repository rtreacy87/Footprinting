from __future__ import annotations

import subprocess
from abc import ABC, abstractmethod
from dataclasses import dataclass


@dataclass
class RunResult:
    tool: str
    command: list[str]
    stdout: str
    stderr: str
    returncode: int
    timed_out: bool = False

    @property
    def success(self) -> bool:
        return self.returncode == 0 and not self.timed_out


class BaseRunner(ABC):
    def __init__(self, timeout: int = 10) -> None:
        self.timeout = timeout

    @property
    @abstractmethod
    def tool_name(self) -> str: ...

    @abstractmethod
    def build_command(self, *args, **kwargs) -> list[str]: ...

    def run(self, *args, **kwargs) -> RunResult:
        cmd = self.build_command(*args, **kwargs)
        timed_out = False
        try:
            proc = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=self.timeout,
            )
            return RunResult(
                tool=self.tool_name,
                command=cmd,
                stdout=proc.stdout,
                stderr=proc.stderr,
                returncode=proc.returncode,
            )
        except subprocess.TimeoutExpired:
            return RunResult(
                tool=self.tool_name,
                command=cmd,
                stdout="",
                stderr="timeout",
                returncode=-1,
                timed_out=True,
            )
        except FileNotFoundError:
            return RunResult(
                tool=self.tool_name,
                command=cmd,
                stdout="",
                stderr=f"{self.tool_name} not found",
                returncode=-2,
            )
