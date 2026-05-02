from __future__ import annotations
import shutil
from abc import ABC, abstractmethod

from ..core.command_runner import CommandRunner
from ..core.result import CommandResult
from ..models.target import Target


class BaseTool(ABC):
    name: str = ""

    def __init__(self, runner: CommandRunner | None = None) -> None:
        self._runner = runner or CommandRunner()

    def is_available(self) -> bool:
        return shutil.which(self.name) is not None

    @abstractmethod
    def build_command(self, **kwargs) -> list[str]:
        raise NotImplementedError

    def run(self, **kwargs) -> CommandResult:
        cmd = self.build_command(**kwargs)
        save_path = kwargs.get("save_path")
        return self._runner.run(cmd, save_path=save_path)
