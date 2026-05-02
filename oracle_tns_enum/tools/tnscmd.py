from __future__ import annotations
from pathlib import Path

from .base import BaseTool
from ..core.result import CommandResult
from ..models.target import Target


class TnsCmdTool(BaseTool):
    name = "tnscmd10g"

    def build_command(self, **kwargs) -> list[str]:
        return [self.name]

    def version(self, target: Target, save_path: Path | None = None) -> CommandResult:
        cmd = [self.name, "version", "-h", target.host, "-p", str(target.port)]
        return self._runner.run(cmd, save_path=save_path)

    def ping(self, target: Target, save_path: Path | None = None) -> CommandResult:
        cmd = [self.name, "ping", "-h", target.host, "-p", str(target.port)]
        return self._runner.run(cmd, save_path=save_path)
