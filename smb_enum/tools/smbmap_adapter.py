from __future__ import annotations

import shutil

from ..models import CommandSpec, Credential


class SmbMapAdapter:
    """Builds smbmap CommandSpec objects."""

    name = "smbmap"

    def is_available(self) -> bool:
        return shutil.which("smbmap") is not None

    def build_anonymous_scan_command(
        self, target: str, timeout: int = 120
    ) -> CommandSpec:
        """Check what shares are visible / readable with no credentials."""
        return CommandSpec(
            tool_name="smbmap",
            argv=["smbmap", "-H", target, "-u", "", "-p", ""],
            timeout_seconds=timeout,
        )

    def build_authenticated_scan_command(
        self,
        target: str,
        credential: Credential,
        timeout: int = 120,
    ) -> CommandSpec:
        """Enumerate share permissions using valid credentials."""
        username = credential.username or ""
        password = credential.password or ""
        argv = ["smbmap", "-H", target, "-u", username, "-p", password]
        if credential.domain:
            argv += ["-d", credential.domain]
        return CommandSpec(
            tool_name="smbmap",
            argv=argv,
            timeout_seconds=timeout,
            sensitive_args=[password] if password else [],
        )

    def build_recursive_scan_command(
        self,
        target: str,
        share: str,
        credential: Credential | None = None,
        timeout: int = 180,
    ) -> CommandSpec:
        """Recursively list files inside a specific share."""
        if credential is None or (credential.username is None and credential.password is None):
            argv = ["smbmap", "-H", target, "-u", "", "-p", "", "-r", share]
            sensitive: list[str] = []
        else:
            username = credential.username or ""
            password = credential.password or ""
            argv = ["smbmap", "-H", target, "-u", username, "-p", password, "-r", share]
            sensitive = [password] if password else []
        return CommandSpec(
            tool_name="smbmap",
            argv=argv,
            timeout_seconds=timeout,
            sensitive_args=sensitive,
        )
