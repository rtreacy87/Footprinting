from __future__ import annotations

import shutil
from pathlib import Path

from ..models import CommandSpec, CommandResult
from ..core.runner import CommandRunner
from ..core.errors import ToolMissingError


class HashcatTool:
    name = "hashcat"

    def __init__(self, runner: CommandRunner) -> None:
        self._runner = runner

    def check_available(self) -> bool:
        return shutil.which("hashcat") is not None

    def build_dictionary_command(self, hash_file: Path, wordlist: Path) -> CommandSpec:
        return CommandSpec(
            tool_name="hashcat",
            argv=["hashcat", "-m", "7300", str(hash_file), str(wordlist), "--force"],
            timeout_seconds=600,
        )

    def build_mask_command(self, hash_file: Path, mask: str, charset: str = "?d?u") -> CommandSpec:
        return CommandSpec(
            tool_name="hashcat",
            argv=["hashcat", "-m", "7300", str(hash_file), "-a", "3", mask,
                  "-1", charset, "--force"],
            timeout_seconds=600,
        )

    def run_dictionary(self, hash_file: Path, wordlist: Path,
                       stdout_path: Path | None = None) -> CommandResult:
        if not self.check_available():
            raise ToolMissingError("hashcat")
        spec = self.build_dictionary_command(hash_file, wordlist)
        return self._runner.run(spec, stdout_path=stdout_path)

    def run_show(self, hash_file: Path) -> CommandResult:
        if not self.check_available():
            raise ToolMissingError("hashcat")
        spec = CommandSpec(
            tool_name="hashcat",
            argv=["hashcat", "-m", "7300", str(hash_file), "--show"],
            timeout_seconds=30,
        )
        return self._runner.run(spec)

    def parse_cracked(self, show_output: str) -> list[tuple[str, str]]:
        """Returns [(username, password), ...] from hashcat --show output."""
        results = []
        for line in show_output.splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            # Format: hash:username:password  or last field is password
            parts = line.split(":")
            if len(parts) >= 2:
                password = parts[-1]
                # Username is typically embedded in the hash blob for IPMI
                results.append(("unknown", password))
        return results
