from __future__ import annotations

from ..core.runner import CommandRunner
from ..models import CommandResult, CommandSpec


class RpcInfoTool:
    def __init__(self, runner: CommandRunner) -> None:
        self._runner = runner

    def list_services(self, target: str, timeout: int = 30) -> CommandResult:
        spec = CommandSpec(
            tool_name="rpcinfo",
            argv=["rpcinfo", "-p", target],
            timeout_seconds=timeout,
        )
        return self._runner.run(spec)
