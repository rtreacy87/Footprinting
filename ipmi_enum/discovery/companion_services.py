from __future__ import annotations

import re

from ..context import ScanContext
from ..core.errors import ToolMissingError
from ..models import CompanionService
from ..tools.nmap import NmapIpmiTool


class CompanionServiceScanner:
    """Scans HTTP/HTTPS/SSH/Telnet ports common to BMC interfaces."""

    def __init__(self, nmap_tool: NmapIpmiTool) -> None:
        self._nmap = nmap_tool

    def run(self, context: ScanContext) -> None:
        target = context.target
        stdout_path = context.raw_path("nmap_companion_services.stdout.txt")
        stderr_path = context.raw_path("nmap_companion_services.stderr.txt")

        try:
            result = self._nmap.run_companion_services(
                target=target,
                stdout_path=stdout_path,
                stderr_path=stderr_path,
            )
        except ToolMissingError as e:
            context.skip_step("companion_services", str(e))
            return

        context.add_evidence(str(stdout_path))
        services = self._parse(result.stdout)
        context.companion_services.extend(services)

    def _parse(self, output: str) -> list[CompanionService]:
        services = []
        for line in output.splitlines():
            m = re.match(r"(\d+)/(tcp|udp)\s+(\S+)\s+(.+)", line.strip())
            if m:
                port, proto, state, rest = m.groups()
                service_name = rest.split()[0] if rest.split() else "unknown"
                banner = " ".join(rest.split()[1:]) if len(rest.split()) > 1 else None
                if state in ("open", "open|filtered"):
                    services.append(CompanionService(
                        port=int(port),
                        protocol=proto,
                        service=service_name,
                        state=state,
                        banner=banner,
                    ))
        return services
