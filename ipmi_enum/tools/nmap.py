from __future__ import annotations

import re
from pathlib import Path

from ..models import CommandSpec, CommandResult, IpmiFinding
from ..core.runner import CommandRunner
from ..core.errors import ToolMissingError
import shutil


class NmapIpmiTool:
    name = "nmap"

    def __init__(self, runner: CommandRunner) -> None:
        self._runner = runner

    def check_available(self) -> bool:
        return shutil.which("nmap") is not None

    def build_version_command(self, target: str, port: int = 623) -> CommandSpec:
        return CommandSpec(
            tool_name="nmap",
            argv=["nmap", "-sU", "--script", "ipmi-version", f"-p{port}", "-Pn", target],
            timeout_seconds=60,
        )

    def run_version(self, target: str, port: int = 623,
                    stdout_path: Path | None = None, stderr_path: Path | None = None) -> CommandResult:
        if not self.check_available():
            raise ToolMissingError("nmap")
        spec = self.build_version_command(target, port)
        return self._runner.run(spec, stdout_path=stdout_path, stderr_path=stderr_path)

    def build_companion_command(self, target: str) -> CommandSpec:
        return CommandSpec(
            tool_name="nmap",
            argv=["nmap", "-sV", "-sC", "-p22,23,80,443,8080,8443", "-Pn", target],
            timeout_seconds=120,
        )

    def run_companion_services(self, target: str,
                                stdout_path: Path | None = None, stderr_path: Path | None = None) -> CommandResult:
        if not self.check_available():
            raise ToolMissingError("nmap")
        spec = self.build_companion_command(target)
        return self._runner.run(spec, stdout_path=stdout_path, stderr_path=stderr_path)

    def parse_version_output(self, output: str, target: str) -> IpmiFinding:
        detected = False
        port = 623
        protocol_version: str | None = None
        user_auth: list[str] = []
        pass_auth: list[str] = []
        privilege_level: str | None = None
        vendor: str | None = None

        if re.search(r"623/udp\s+open", output, re.IGNORECASE):
            detected = True

        m = re.search(r"Version:\s*(\S+)", output, re.IGNORECASE)
        if m:
            protocol_version = m.group(1)
            detected = True

        m = re.search(r"UserAuth:\s*(.+)", output, re.IGNORECASE)
        if m:
            user_auth = [x.strip() for x in m.group(1).split(",")]

        m = re.search(r"PassAuth:\s*(.+)", output, re.IGNORECASE)
        if m:
            pass_auth = [x.strip() for x in m.group(1).split(",")]

        m = re.search(r"Level:\s*(.+)", output, re.IGNORECASE)
        if m:
            privilege_level = m.group(1).strip()

        # Vendor/MAC hint
        m = re.search(r"MAC Address:.*?\((.+?)\)", output, re.IGNORECASE)
        if m:
            vendor = m.group(1).strip()

        return IpmiFinding(
            target=target,
            ipmi_detected=detected,
            port=port,
            protocol_version=protocol_version,
            user_auth=user_auth,
            pass_auth=pass_auth,
            privilege_level=privilege_level,
            vendor=vendor,
        )
