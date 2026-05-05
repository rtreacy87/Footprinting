from __future__ import annotations

from pathlib import Path

from ..executors.base import ExecutionResult
from .base import BaseTool


class SwaksTool(BaseTool):
    """Wrap swaks for SMTP testing (used for relay/spoofing when safe_mode=False)."""

    tool_name = "swaks"

    def test_connection(
        self,
        server: str,
        port: int,
        from_addr: str,
        to_addr: str,
        timeout: int = 30,
        output_path: Path | None = None,
    ) -> ExecutionResult:
        argv = [
            "swaks",
            "--server", server,
            "--port", str(port),
            "--from", from_addr,
            "--to", to_addr,
            "--quit-after", "RCPT",
            "--timeout", str(timeout),
        ]
        return self._executor.run(argv, stdout_path=output_path, timeout=timeout + 10)

    def test_tls(
        self,
        server: str,
        port: int,
        from_addr: str,
        to_addr: str,
        timeout: int = 30,
        output_path: Path | None = None,
    ) -> ExecutionResult:
        argv = [
            "swaks",
            "--server", server,
            "--port", str(port),
            "--from", from_addr,
            "--to", to_addr,
            "--tls",
            "--quit-after", "RCPT",
            "--timeout", str(timeout),
        ]
        return self._executor.run(argv, stdout_path=output_path, timeout=timeout + 10)
