from __future__ import annotations

import shutil

from ..models import CommandSpec, Credential


class CrackMapExecAdapter:
    """Builds crackmapexec / netexec CommandSpec objects.

    Prefers ``netexec`` binary; falls back to ``crackmapexec``.
    """

    name = "crackmapexec"

    def _binary(self) -> str:
        if shutil.which("netexec"):
            return "netexec"
        return "crackmapexec"

    def is_available(self) -> bool:
        return shutil.which("netexec") is not None or shutil.which("crackmapexec") is not None

    def build_smb_scan_command(
        self,
        target: str,
        credential: Credential | None = None,
        timeout: int = 120,
    ) -> CommandSpec:
        """Basic SMB scan (version, signing, OS detection)."""
        binary = self._binary()
        argv = [binary, "smb", target]
        sensitive: list[str] = []
        if credential and credential.username:
            password = credential.password or ""
            argv += ["-u", credential.username, "-p", password]
            sensitive = [password] if password else []
        return CommandSpec(
            tool_name="crackmapexec",
            argv=argv,
            timeout_seconds=timeout,
            sensitive_args=sensitive,
        )

    def build_share_enum_command(
        self,
        target: str,
        credential: Credential | None = None,
        timeout: int = 120,
    ) -> CommandSpec:
        """Enumerate shares with optional credentials."""
        binary = self._binary()
        argv = [binary, "smb", target, "--shares"]
        sensitive: list[str] = []
        if credential and credential.username:
            password = credential.password or ""
            argv += ["-u", credential.username, "-p", password]
            sensitive = [password] if password else []
        else:
            argv += ["-u", "", "-p", ""]
        return CommandSpec(
            tool_name="crackmapexec",
            argv=argv,
            timeout_seconds=timeout,
            sensitive_args=sensitive,
        )
