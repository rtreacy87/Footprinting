from __future__ import annotations

import shutil
from pathlib import Path

from ..models import CommandSpec, Credential


class SmbClientAdapter:
    """Builds smbclient CommandSpec objects."""

    name = "smbclient"

    def is_available(self) -> bool:
        return shutil.which("smbclient") is not None

    def build_list_shares_command(
        self,
        target: str,
        credential: Credential | None = None,
        timeout: int = 60,
    ) -> CommandSpec:
        """List shares on the target.  Uses null session when no credential given."""
        if credential is None or (credential.username is None and credential.password is None):
            argv = ["smbclient", "-N", "-L", f"//{target}"]
            sensitive: list[str] = []
        else:
            password = credential.password or ""
            argv = [
                "smbclient", "-L", f"//{target}",
                "-U", f"{credential.username}%{password}",
            ]
            sensitive = [f"{credential.username}%{password}"]
        return CommandSpec(
            tool_name="smbclient",
            argv=argv,
            timeout_seconds=timeout,
            sensitive_args=sensitive,
        )

    def build_recursive_list_command(
        self,
        target: str,
        share: str,
        credential: Credential | None = None,
        timeout: int = 120,
    ) -> CommandSpec:
        """Recursively list files inside a share using recurse + ls."""
        if credential is None or (credential.username is None and credential.password is None):
            argv = [
                "smbclient", f"//{target}/{share}",
                "-N", "-c", "recurse;ls",
            ]
            sensitive: list[str] = []
        else:
            password = credential.password or ""
            argv = [
                "smbclient", f"//{target}/{share}",
                "-U", f"{credential.username}%{password}",
                "-c", "recurse;ls",
            ]
            sensitive = [f"{credential.username}%{password}"]
        return CommandSpec(
            tool_name="smbclient",
            argv=argv,
            timeout_seconds=timeout,
            sensitive_args=sensitive,
        )

    def build_get_file_command(
        self,
        target: str,
        share: str,
        remote_path: str,
        local_path: Path,
        credential: Credential | None = None,
        timeout: int = 60,
    ) -> CommandSpec:
        """Download a single file from an SMB share.

        Handles Windows-style paths (backslash) by issuing a ``cd`` before
        ``get`` so smbclient operates in the correct directory.
        """
        normalized = remote_path.replace("/", "\\").lstrip("\\")
        parts = [p for p in normalized.split("\\") if p]
        remote_file = parts[-1] if parts else normalized
        remote_dir = "\\".join(parts[:-1]) if len(parts) > 1 else ""

        commands: list[str] = []
        if remote_dir:
            commands.append(f'cd "{remote_dir}"')
        commands.append(f'get "{remote_file}" "{local_path}"')
        get_cmd = ";".join(commands)

        if credential is None or (credential.username is None and credential.password is None):
            argv = [
                "smbclient", f"//{target}/{share}",
                "-N", "-c", get_cmd,
            ]
            sensitive: list[str] = []
        else:
            password = credential.password or ""
            argv = [
                "smbclient", f"//{target}/{share}",
                "-U", f"{credential.username}%{password}",
                "-c", get_cmd,
            ]
            sensitive = [f"{credential.username}%{password}"]
        return CommandSpec(
            tool_name="smbclient",
            argv=argv,
            timeout_seconds=timeout,
            sensitive_args=sensitive,
        )
