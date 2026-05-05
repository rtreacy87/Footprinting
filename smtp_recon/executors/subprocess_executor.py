from __future__ import annotations

import logging
import subprocess
import time
from pathlib import Path

from .base import ExecutionResult

logger = logging.getLogger(__name__)


class SubprocessExecutor:
    """Run an external command, optionally writing stdout/stderr to files."""

    def __init__(self, timeout: int = 120) -> None:
        self._timeout = timeout

    def run(
        self,
        argv: list[str],
        stdout_path: Path | None = None,
        stderr_path: Path | None = None,
        timeout: int | None = None,
        env: dict[str, str] | None = None,
    ) -> ExecutionResult:
        effective_timeout = timeout if timeout is not None else self._timeout
        logger.debug("Running: %s", " ".join(argv))

        start = time.monotonic()
        try:
            proc = subprocess.run(
                argv,
                capture_output=True,
                text=True,
                timeout=effective_timeout,
                env=env,
            )
        except subprocess.TimeoutExpired:
            elapsed = time.monotonic() - start
            logger.warning("Command timed out after %.1fs: %s", elapsed, argv[0])
            return ExecutionResult(
                stdout="",
                stderr=f"Command timed out after {effective_timeout}s",
                return_code=-1,
                elapsed_seconds=elapsed,
            )
        except FileNotFoundError:
            elapsed = time.monotonic() - start
            logger.warning("Tool not found: %s", argv[0])
            return ExecutionResult(
                stdout="",
                stderr=f"Tool not found: {argv[0]}",
                return_code=-2,
                elapsed_seconds=elapsed,
            )

        elapsed = time.monotonic() - start
        stdout_str = proc.stdout or ""
        stderr_str = proc.stderr or ""

        if stdout_path:
            stdout_path.parent.mkdir(parents=True, exist_ok=True)
            stdout_path.write_text(stdout_str, encoding="utf-8")

        if stderr_path:
            stderr_path.parent.mkdir(parents=True, exist_ok=True)
            stderr_path.write_text(stderr_str, encoding="utf-8")

        logger.debug(
            "Command finished rc=%d in %.1fs: %s",
            proc.returncode,
            elapsed,
            argv[0],
        )
        return ExecutionResult(
            stdout=stdout_str,
            stderr=stderr_str,
            return_code=proc.returncode,
            elapsed_seconds=elapsed,
        )
