from __future__ import annotations

import shutil
from pathlib import Path

from ..models import CommandSpec, CommandResult
from ..core.runner import CommandRunner
from ..core.errors import ToolMissingError


class IpmiTool:
    name = "ipmitool"

    _SAFE_SUBCOMMANDS = {
        "mc info", "chassis status", "user list", "channel info",
        "lan print", "sensor", "sel info", "sel list",
    }

    def __init__(self, runner: CommandRunner) -> None:
        self._runner = runner

    def check_available(self) -> bool:
        return shutil.which("ipmitool") is not None

    def _build(self, target: str, username: str, password: str, subcmd: list[str]) -> CommandSpec:
        argv = [
            "ipmitool", "-I", "lanplus",
            "-H", target,
            "-U", username,
            "-P", password,
        ] + subcmd
        return CommandSpec(
            tool_name="ipmitool",
            argv=argv,
            timeout_seconds=30,
            sensitive_args=[password],
        )

    def run_mc_info(self, target: str, username: str, password: str,
                    stdout_path: Path | None = None) -> CommandResult:
        if not self.check_available():
            raise ToolMissingError("ipmitool")
        spec = self._build(target, username, password, ["mc", "info"])
        return self._runner.run(spec, stdout_path=stdout_path)

    def run_chassis_status(self, target: str, username: str, password: str,
                           stdout_path: Path | None = None) -> CommandResult:
        if not self.check_available():
            raise ToolMissingError("ipmitool")
        spec = self._build(target, username, password, ["chassis", "status"])
        return self._runner.run(spec, stdout_path=stdout_path)

    def run_user_list(self, target: str, username: str, password: str,
                      stdout_path: Path | None = None) -> CommandResult:
        if not self.check_available():
            raise ToolMissingError("ipmitool")
        spec = self._build(target, username, password, ["user", "list"])
        return self._runner.run(spec, stdout_path=stdout_path)

    def run_channel_info(self, target: str, username: str, password: str,
                         stdout_path: Path | None = None) -> CommandResult:
        if not self.check_available():
            raise ToolMissingError("ipmitool")
        spec = self._build(target, username, password, ["channel", "info"])
        return self._runner.run(spec, stdout_path=stdout_path)

    def run_lan_print(self, target: str, username: str, password: str,
                      stdout_path: Path | None = None) -> CommandResult:
        if not self.check_available():
            raise ToolMissingError("ipmitool")
        spec = self._build(target, username, password, ["lan", "print"])
        return self._runner.run(spec, stdout_path=stdout_path)

    def test_credential(self, target: str, username: str, password: str) -> bool:
        if not self.check_available():
            return False
        try:
            spec = self._build(target, username, password, ["chassis", "status"])
            result = self._runner.run(spec)
            return result.return_code == 0
        except Exception:
            return False
