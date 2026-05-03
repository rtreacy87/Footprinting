from __future__ import annotations

import shutil

from ..models import CommandSpec, Credential


class Enum4LinuxAdapter:
    """Builds enum4linux / enum4linux-ng CommandSpec objects.

    Prefers the ``enum4linux-ng`` binary; falls back to ``enum4linux``.
    """

    name = "enum4linux"

    def _binary(self) -> str:
        if shutil.which("enum4linux-ng"):
            return "enum4linux-ng"
        return "enum4linux"

    def is_available(self) -> bool:
        return shutil.which("enum4linux-ng") is not None or shutil.which("enum4linux") is not None

    def build_full_scan_command(
        self,
        target: str,
        credential: Credential | None = None,
        timeout: int = 300,
    ) -> CommandSpec:
        """Run a full enum4linux scan against the target."""
        binary = self._binary()
        if binary == "enum4linux-ng":
            argv = [binary, "-A", target]
            if credential and credential.username:
                password = credential.password or ""
                argv += ["-u", credential.username, "-p", password]
                sensitive = [password] if password else []
            else:
                sensitive = []
        else:
            # legacy enum4linux flags
            argv = [binary, "-a", target]
            if credential and credential.username:
                password = credential.password or ""
                argv += ["-u", credential.username, "-p", password]
                sensitive = [password] if password else []
            else:
                sensitive = []

        return CommandSpec(
            tool_name="enum4linux",
            argv=argv,
            timeout_seconds=timeout,
            sensitive_args=sensitive,
        )
