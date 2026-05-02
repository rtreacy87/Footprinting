from __future__ import annotations
import subprocess
from datetime import datetime, timezone
from pathlib import Path

from .result import CommandResult


class CommandRunner:
    def __init__(self, timeout: int = 120) -> None:
        self._timeout = timeout

    def run(self, command: list[str], save_path: Path | None = None) -> CommandResult:
        started = datetime.now(timezone.utc).isoformat()
        try:
            proc = subprocess.run(
                command,
                capture_output=True,
                text=True,
                timeout=self._timeout,
            )
            completed = datetime.now(timezone.utc).isoformat()
            result = CommandResult(
                tool_name=command[0],
                command=command,
                started_at=started,
                completed_at=completed,
                return_code=proc.returncode,
                stdout=proc.stdout,
                stderr=proc.stderr,
            )
        except subprocess.TimeoutExpired:
            completed = datetime.now(timezone.utc).isoformat()
            result = CommandResult(
                tool_name=command[0],
                command=command,
                started_at=started,
                completed_at=completed,
                return_code=-1,
                stdout="",
                stderr=f"Command timed out after {self._timeout}s",
            )
        except FileNotFoundError:
            completed = datetime.now(timezone.utc).isoformat()
            result = CommandResult(
                tool_name=command[0],
                command=command,
                started_at=started,
                completed_at=completed,
                return_code=-1,
                stdout="",
                stderr=f"Command not found: {command[0]}",
            )

        if save_path is not None:
            save_path.parent.mkdir(parents=True, exist_ok=True)
            save_path.write_text(result.output, encoding="utf-8")
            result.raw_output_path = str(save_path)

        return result
