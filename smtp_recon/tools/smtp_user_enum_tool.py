from __future__ import annotations

import re
import shutil
from pathlib import Path

from ..executors.base import ExecutionResult
from ..executors.subprocess_executor import SubprocessExecutor
from .base import BaseTool

_LOCAL_SCRIPT_NAME = "smtp-user-enum.pl"

# Project root: smtp_recon/tools/ -> smtp_recon/ -> project/
_PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent


class SmtpUserEnumTool(BaseTool):
    """
    Wrap smtp-user-enum — tries the system binary first, then the local
    smtp-user-enum.pl Perl script in the project directory.
    """

    tool_name = "smtp-user-enum"

    @classmethod
    def find_executable(cls) -> tuple[list[str], bool]:
        """Return (argv_prefix, found)."""
        sys_bin = shutil.which("smtp-user-enum")
        if sys_bin:
            return [sys_bin], True

        local_pl = _PROJECT_ROOT / _LOCAL_SCRIPT_NAME
        if local_pl.exists():
            perl = shutil.which("perl") or "perl"
            return [perl, str(local_pl)], True

        return [], False

    @classmethod
    def is_available(cls) -> bool:
        _, found = cls.find_executable()
        return found

    def enumerate(
        self,
        target: str,
        port: int,
        userlist_path: Path,
        mode: str = "VRFY",
        workers: int = 60,
        query_timeout: int = 20,
        timeout: int = 300,
        output_path: Path | None = None,
    ) -> ExecutionResult:
        prefix, found = self.find_executable()
        if not found:
            return ExecutionResult(
                stdout="",
                stderr="smtp-user-enum not found (tried PATH and local smtp-user-enum.pl)",
                return_code=-2,
            )

        argv = prefix + [
            "-M", mode,
            "-U", str(userlist_path),
            "-t", target,
            "-p", str(port),
            "-m", str(workers),
            "-w", str(query_timeout),
        ]
        return self._executor.run(argv, stdout_path=output_path, timeout=timeout)

    @staticmethod
    def parse_hits(output: str, target: str) -> list[str]:
        """Parse smtp-user-enum output and return confirmed usernames.

        Matches lines like: "10.129.42.195: robin exists"
        """
        pattern = re.compile(
            rf"^{re.escape(target)}:\s+(\S+)\s+exists",
            re.IGNORECASE | re.MULTILINE,
        )
        return [m.group(1) for m in pattern.finditer(output)]
