from __future__ import annotations
import shutil
from pathlib import Path

from .base import BaseTool
from ..core.result import CommandResult
from ..models.target import Target


class OdatTool(BaseTool):
    name = "odat.py"

    def __init__(self, odat_path: str = "odat.py", **kwargs) -> None:
        super().__init__(**kwargs)
        self._odat_path = odat_path

    def is_available(self) -> bool:
        return shutil.which(self._odat_path) is not None

    def build_command(self, **kwargs) -> list[str]:
        return [self._odat_path]

    def tnscmd_ping(self, target: Target, save_path: Path | None = None) -> CommandResult:
        cmd = [
            self._odat_path, "tnscmd",
            "-s", target.host,
            "-p", str(target.port),
            "--ping",
        ]
        return self._runner.run(cmd, save_path=save_path)

    def sid_guesser(self, target: Target, sid_file: str | None = None, save_path: Path | None = None) -> CommandResult:
        cmd = [
            self._odat_path, "sidguesser",
            "-s", target.host,
            "-p", str(target.port),
        ]
        if sid_file:
            cmd += ["--sids-file", sid_file]
        return self._runner.run(cmd, save_path=save_path)

    def password_guesser(
        self,
        target: Target,
        sid: str,
        accounts_file: str | None = None,
        save_path: Path | None = None,
    ) -> CommandResult:
        cmd = [
            self._odat_path, "passwordguesser",
            "-s", target.host,
            "-p", str(target.port),
            "-d", sid,
        ]
        if accounts_file:
            cmd += ["--accounts-file", accounts_file]
        return self._runner.run(cmd, save_path=save_path)

    def all_modules(
        self,
        target: Target,
        sid: str,
        username: str,
        password: str,
        save_path: Path | None = None,
    ) -> CommandResult:
        cmd = [
            self._odat_path, "all",
            "-s", target.host,
            "-p", str(target.port),
            "-d", sid,
            "-U", username,
            "-P", password,
        ]
        return self._runner.run(cmd, save_path=save_path)
