from __future__ import annotations
from pathlib import Path

from .base import BaseTool
from ..core.result import CommandResult
from ..models.target import Target


class HydraTool(BaseTool):
    name = "hydra"

    def build_command(self, **kwargs) -> list[str]:
        return ["hydra"]

    def oracle_listener_guess(
        self,
        target: Target,
        users_file: str,
        passwords_file: str,
        save_path: Path | None = None,
    ) -> CommandResult:
        cmd = [
            "hydra",
            "-L", users_file,
            "-P", passwords_file,
            "-s", str(target.port),
            target.host,
            "oracle-listener",
        ]
        return self._runner.run(cmd, save_path=save_path)
