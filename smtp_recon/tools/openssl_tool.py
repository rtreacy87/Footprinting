from __future__ import annotations

from pathlib import Path

from ..executors.base import ExecutionResult
from .base import BaseTool


class OpenSslTool(BaseTool):
    """Wrap openssl s_client for TLS inspection."""

    tool_name = "openssl"

    def s_client_starttls(
        self,
        host: str,
        port: int,
        timeout: int = 30,
        output_path: Path | None = None,
    ) -> ExecutionResult:
        argv = [
            "openssl", "s_client",
            "-connect", f"{host}:{port}",
            "-starttls", "smtp",
            "-brief",
        ]
        return self._executor.run(argv, stdout_path=output_path, timeout=timeout + 5)

    def s_client_direct(
        self,
        host: str,
        port: int,
        timeout: int = 30,
        output_path: Path | None = None,
    ) -> ExecutionResult:
        argv = [
            "openssl", "s_client",
            "-connect", f"{host}:{port}",
            "-brief",
        ]
        return self._executor.run(argv, stdout_path=output_path, timeout=timeout + 5)
