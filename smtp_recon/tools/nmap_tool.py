from __future__ import annotations

from pathlib import Path

from ..executors.base import ExecutionResult
from ..executors.subprocess_executor import SubprocessExecutor
from .base import BaseTool


class NmapSmtpTool(BaseTool):
    """Wrap nmap for SMTP port discovery and banner grabbing."""

    tool_name = "nmap"

    def port_scan(
        self,
        target: str,
        ports: list[int],
        timeout: int = 120,
        output_path: Path | None = None,
    ) -> ExecutionResult:
        port_str = ",".join(str(p) for p in ports)
        argv = ["nmap", "-Pn", "-sV", f"-p{port_str}", "--open", target]
        result = self._executor.run(argv, stdout_path=output_path, timeout=timeout)
        return result

    def script_scan(
        self,
        target: str,
        ports: list[int],
        scripts: str = "smtp-commands,smtp-open-relay",
        timeout: int = 120,
        output_path: Path | None = None,
    ) -> ExecutionResult:
        port_str = ",".join(str(p) for p in ports)
        argv = [
            "nmap", "-Pn", "-sV",
            f"-p{port_str}",
            "--script", scripts,
            target,
        ]
        return self._executor.run(argv, stdout_path=output_path, timeout=timeout)
