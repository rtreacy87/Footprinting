from __future__ import annotations

from ..context import ScanContext
from ..tools.ipmitool import IpmiTool


class PostAuthInventory:
    """Collects safe read-only post-auth data via ipmitool."""

    def __init__(self, ipmitool: IpmiTool) -> None:
        self._tool = ipmitool

    def run(self, context: ScanContext, username: str, password: str) -> None:
        target = context.target
        commands = [
            ("mc_info", self._tool.run_mc_info),
            ("chassis_status", self._tool.run_chassis_status),
            ("user_list", self._tool.run_user_list),
            ("channel_info", self._tool.run_channel_info),
            ("lan_print", self._tool.run_lan_print),
        ]

        for name, method in commands:
            stdout_path = context.raw_path(f"ipmitool_{name}.stdout.txt")
            try:
                result = method(target, username, password, stdout_path=stdout_path)
                if result.return_code == 0:
                    context.add_evidence(str(stdout_path))
            except Exception as e:
                context.add_error(f"ipmitool {name} failed: {e}")
