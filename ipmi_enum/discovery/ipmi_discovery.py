from __future__ import annotations

from ..context import ScanContext
from ..core.errors import ToolMissingError
from ..tools.nmap import NmapIpmiTool


class IpmiDiscovery:
    """Detects IPMI on UDP/623 and extracts version/auth capabilities."""

    def __init__(self, nmap_tool: NmapIpmiTool) -> None:
        self._nmap = nmap_tool

    def run(self, context: ScanContext) -> None:
        target = context.target
        stdout_path = context.raw_path("nmap_ipmi_version.stdout.txt")
        stderr_path = context.raw_path("nmap_ipmi_version.stderr.txt")

        try:
            result = self._nmap.run_version(
                target=target,
                port=623,
                stdout_path=stdout_path,
                stderr_path=stderr_path,
            )
        except ToolMissingError as e:
            context.add_error(f"nmap not available: {e}")
            return

        context.add_evidence(str(stdout_path))
        finding = self._nmap.parse_version_output(result.stdout, target)
        context.ipmi_finding = finding
