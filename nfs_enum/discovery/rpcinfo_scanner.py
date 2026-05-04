from __future__ import annotations

import json
import re

from ..context import ScanContext
from ..models import RpcService
from ..tools.rpcinfo import RpcInfoTool


_LINE_RE = re.compile(
    r"(\d+)\s+(\d+)\s+(tcp|udp)\s+(\d+)\s*(\S*)"
)


class RpcInfoScanner:
    def __init__(self, rpcinfo: RpcInfoTool) -> None:
        self._rpcinfo = rpcinfo

    def run(self, context: ScanContext) -> None:
        result = self._rpcinfo.list_services(context.target)

        raw_path = context.path("discovery", "rpcinfo_raw.txt")
        raw_path.write_text(result.stdout + result.stderr, encoding="utf-8")

        if context.discovery is None:
            return

        services: list[RpcService] = []
        for line in result.stdout.splitlines():
            m = _LINE_RE.search(line)
            if m:
                services.append(RpcService(
                    program=m.group(1),
                    version=m.group(2),
                    protocol=m.group(3),
                    port=int(m.group(4)),
                    service_name=m.group(5),
                ))

        context.discovery.rpcinfo_raw = result.stdout
        context.discovery.rpc_services = services

        parsed = [
            {
                "program": s.program,
                "version": s.version,
                "protocol": s.protocol,
                "port": s.port,
                "service_name": s.service_name,
            }
            for s in services
        ]
        context.path("discovery", "rpcinfo_parsed.json").write_text(
            json.dumps(parsed, indent=2), encoding="utf-8"
        )
