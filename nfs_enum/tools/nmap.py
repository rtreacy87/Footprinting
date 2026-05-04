from __future__ import annotations

from pathlib import Path

from ..core.runner import CommandRunner
from ..models import CommandResult, CommandSpec


class NmapNfsTool:
    def __init__(self, runner: CommandRunner) -> None:
        self._runner = runner

    def port_scan(self, target: str, timeout: int = 120) -> CommandResult:
        spec = CommandSpec(
            tool_name="nmap",
            argv=["nmap", "-Pn", "-sV", "-p111,2049", target],
            timeout_seconds=timeout,
        )
        return self._runner.run(spec)

    def showmount_script(self, target: str, timeout: int = 120) -> CommandResult:
        spec = CommandSpec(
            tool_name="nmap",
            argv=["nmap", "-Pn", "-sV", "-p111,2049", "--script", "nfs-showmount", target],
            timeout_seconds=timeout,
        )
        return self._runner.run(spec)

    def nfs_scripts(self, target: str, timeout: int = 120) -> CommandResult:
        spec = CommandSpec(
            tool_name="nmap",
            argv=[
                "nmap", "-Pn", "-p111,2049",
                "--script", "nfs-ls,nfs-showmount,nfs-statfs",
                target,
            ],
            timeout_seconds=timeout,
        )
        return self._runner.run(spec)

    def run_nse_file(
        self,
        target: str,
        nse_path: Path,
        script_args: str,
        port: int = 111,
        timeout: int = 60,
        use_sudo: bool = False,
    ) -> CommandResult:
        base_argv = [
            "nmap", "-Pn", f"-p{port}",
            "--script", str(nse_path),
            "--script-args", script_args,
            target,
        ]
        argv = (["sudo", "-n"] + base_argv) if use_sudo else base_argv
        spec = CommandSpec(
            tool_name="nmap",
            argv=argv,
            timeout_seconds=timeout,
        )
        return self._runner.run(spec)
