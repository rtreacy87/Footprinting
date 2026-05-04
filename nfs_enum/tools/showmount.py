from __future__ import annotations

from ..core.runner import CommandRunner
from ..models import CommandResult, CommandSpec


class ShowmountTool:
    def __init__(self, runner: CommandRunner) -> None:
        self._runner = runner

    def show_exports(self, target: str, timeout: int = 30) -> CommandResult:
        spec = CommandSpec(
            tool_name="showmount",
            argv=["showmount", "-e", target],
            timeout_seconds=timeout,
        )
        return self._runner.run(spec)
