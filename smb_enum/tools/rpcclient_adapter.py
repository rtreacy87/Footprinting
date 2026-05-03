from __future__ import annotations

import shutil

from ..models import CommandSpec, Credential


class RpcClientAdapter:
    """Builds rpcclient CommandSpec objects."""

    name = "rpcclient"

    def is_available(self) -> bool:
        return shutil.which("rpcclient") is not None

    def build_null_session_command(
        self,
        target: str,
        rpc_command: str,
        timeout: int = 60,
    ) -> CommandSpec:
        """Run an arbitrary rpcclient command via null session."""
        return CommandSpec(
            tool_name="rpcclient",
            argv=["rpcclient", "-U", "", "-N", target, "-c", rpc_command],
            timeout_seconds=timeout,
        )

    def build_user_enum_command(
        self,
        target: str,
        timeout: int = 60,
    ) -> CommandSpec:
        """Enumerate domain users via null session."""
        return CommandSpec(
            tool_name="rpcclient",
            argv=["rpcclient", "-U", "", "-N", target, "-c", "enumdomusers"],
            timeout_seconds=timeout,
        )

    def build_group_enum_command(
        self,
        target: str,
        timeout: int = 60,
    ) -> CommandSpec:
        """Enumerate domain groups via null session."""
        return CommandSpec(
            tool_name="rpcclient",
            argv=["rpcclient", "-U", "", "-N", target, "-c", "enumdomgroups"],
            timeout_seconds=timeout,
        )

    def build_domain_info_command(
        self,
        target: str,
        timeout: int = 60,
    ) -> CommandSpec:
        """Query domain information via querydominfo."""
        return CommandSpec(
            tool_name="rpcclient",
            argv=["rpcclient", "-U", "", "-N", target, "-c", "querydominfo"],
            timeout_seconds=timeout,
        )

    def build_share_info_command(
        self,
        target: str,
        share: str,
        timeout: int = 60,
    ) -> CommandSpec:
        """Query share details (path, remark) via netsharegetinfo."""
        return CommandSpec(
            tool_name="rpcclient",
            argv=["rpcclient", "-U", "", "-N", target, "-c", f"netsharegetinfo {share}"],
            timeout_seconds=timeout,
        )
