from __future__ import annotations

import re
import shutil
from pathlib import Path

from ..models import CommandSpec, CommandResult, CompanionService
from ..core.runner import CommandRunner
from ..core.errors import ToolMissingError


class CurlTool:
    name = "curl"

    def __init__(self, runner: CommandRunner) -> None:
        self._runner = runner

    def check_available(self) -> bool:
        return shutil.which("curl") is not None

    def build_head_command(self, url: str) -> CommandSpec:
        return CommandSpec(
            tool_name="curl",
            argv=["curl", "-k", "-I", "--max-time", "10", url],
            timeout_seconds=15,
        )

    def build_get_command(self, url: str) -> CommandSpec:
        return CommandSpec(
            tool_name="curl",
            argv=["curl", "-k", "-L", "--max-time", "10",
                  "--max-filesize", "1048576", url],
            timeout_seconds=15,
        )

    def run_head(self, url: str, stdout_path: Path | None = None) -> CommandResult:
        if not self.check_available():
            raise ToolMissingError("curl")
        spec = self.build_head_command(url)
        return self._runner.run(spec, stdout_path=stdout_path)

    def run_get(self, url: str, stdout_path: Path | None = None) -> CommandResult:
        if not self.check_available():
            raise ToolMissingError("curl")
        spec = self.build_get_command(url)
        return self._runner.run(spec, stdout_path=stdout_path)

    def parse_vendor_hints(self, headers: str, body: str) -> list[str]:
        text = (headers + " " + body).lower()
        vendors = []
        if "idrac" in text or "dell" in text:
            vendors.append("Dell iDRAC")
        if "ilo" in text or "hewlett packard" in text or "hpe" in text:
            vendors.append("HP iLO")
        if "supermicro" in text or "aten" in text or "megarac" in text:
            vendors.append("Supermicro")
        if "xclarity" in text or "imm" in text or "lenovo" in text:
            vendors.append("Lenovo IMM/XClarity")
        if "cimc" in text or "cisco integrated management" in text:
            vendors.append("Cisco CIMC")
        return vendors

    def parse_title(self, body: str) -> str | None:
        m = re.search(r"<title[^>]*>([^<]+)</title>", body, re.IGNORECASE)
        return m.group(1).strip() if m else None
