from __future__ import annotations

import subprocess
import uuid
from datetime import datetime, timezone
from pathlib import Path

from ..models import CommandResult, CommandSpec
from .errors import CommandTimeoutError


class CommandRunner:
    def __init__(self, output_base: Path | None = None) -> None:
        self._output_base = output_base

    def run(
        self,
        spec: "CommandSpec",
        stdout_path: Path | None = None,
        stderr_path: Path | None = None,
    ) -> CommandResult:
        command_id = str(uuid.uuid4())[:8]
        started_at = datetime.now(timezone.utc).isoformat()

        try:
            proc = subprocess.run(
                spec.argv,
                capture_output=True,
                text=True,
                timeout=spec.timeout_seconds,
                cwd=spec.cwd,
                env=spec.env,
            )
        except subprocess.TimeoutExpired:
            raise CommandTimeoutError(spec.tool_name, spec.timeout_seconds)

        ended_at = datetime.now(timezone.utc).isoformat()
        stdout_str = proc.stdout or ""
        stderr_str = proc.stderr or ""

        stdout_file: str | None = None
        stderr_file: str | None = None

        if stdout_path:
            stdout_path.parent.mkdir(parents=True, exist_ok=True)
            stdout_path.write_text(stdout_str, encoding="utf-8")
            stdout_file = str(stdout_path)

        if stderr_path:
            stderr_path.parent.mkdir(parents=True, exist_ok=True)
            stderr_path.write_text(stderr_str, encoding="utf-8")
            stderr_file = str(stderr_path)

        return CommandResult(
            command_id=command_id,
            tool_name=spec.tool_name,
            return_code=proc.returncode,
            stdout=stdout_str,
            stderr=stderr_str,
            stdout_path=stdout_file,
            stderr_path=stderr_file,
            started_at=started_at,
            ended_at=ended_at,
        )
