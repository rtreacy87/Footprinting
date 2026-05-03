from __future__ import annotations

import shutil

from ..models import CommandSpec, Credential


class NmapAdapter:
    """Builds nmap CommandSpec objects for SMB enumeration."""

    name = "nmap"

    def is_available(self) -> bool:
        return shutil.which("nmap") is not None

    def build_version_scan_command(self, target: str, timeout: int = 120) -> CommandSpec:
        """Version + service scan on SMB ports."""
        return CommandSpec(
            tool_name="nmap",
            argv=[
                "nmap", "-sV", "-p", "139,445",
                "--open", "-Pn", target,
            ],
            timeout_seconds=timeout,
        )

    def build_smb_scripts_command(self, target: str, timeout: int = 120) -> CommandSpec:
        """Run standard SMB NSE scripts for signing, OS, dialect detection."""
        return CommandSpec(
            tool_name="nmap",
            argv=[
                "nmap", "-p", "139,445",
                "--script",
                "smb-security-mode,smb2-security-mode,smb-os-discovery,smb-protocols",
                "-Pn", target,
            ],
            timeout_seconds=timeout,
        )

    def build_smb1_check_command(self, target: str, timeout: int = 120) -> CommandSpec:
        """Probe specifically for SMBv1 availability."""
        return CommandSpec(
            tool_name="nmap",
            argv=[
                "nmap", "-p", "445",
                "--script", "smb-protocols",
                "-Pn", target,
            ],
            timeout_seconds=timeout,
        )
