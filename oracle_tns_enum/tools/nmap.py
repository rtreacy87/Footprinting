from __future__ import annotations
from pathlib import Path

from .base import BaseTool
from ..core.result import CommandResult
from ..models.target import Target


class NmapTool(BaseTool):
    name = "nmap"

    def build_command(self, **kwargs) -> list[str]:
        return ["nmap"]

    def service_detection(self, target: Target, save_path: Path | None = None) -> CommandResult:
        cmd = [
            "nmap", "-p", str(target.port),
            "-sV", "-sC", "--open", "-Pn",
            "--script", "oracle-tns-version",
            target.host,
        ]
        return self._runner.run(cmd, save_path=save_path)

    def sid_brute(self, target: Target, save_path: Path | None = None) -> CommandResult:
        cmd = [
            "nmap", "-p", str(target.port),
            "--script", "oracle-sid-brute",
            "-Pn",
            target.host,
        ]
        return self._runner.run(cmd, save_path=save_path)

    def oracle_brute(self, target: Target, sid: str, save_path: Path | None = None) -> CommandResult:
        cmd = [
            "nmap", "-p", str(target.port),
            "--script", "oracle-brute",
            "--script-args", f"oracle-brute.sid={sid}",
            "-Pn",
            target.host,
        ]
        return self._runner.run(cmd, save_path=save_path)
