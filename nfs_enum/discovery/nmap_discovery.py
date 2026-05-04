from __future__ import annotations

import json
import re

from ..context import ScanContext
from ..models import DiscoveryResult
from ..tools.nmap import NmapNfsTool


class NmapDiscovery:
    def __init__(self, nmap: NmapNfsTool) -> None:
        self._nmap = nmap

    def run(self, context: ScanContext) -> None:
        result = self._nmap.port_scan(
            context.target,
            timeout=context.config.options.nmap_timeout_seconds,
        )

        raw_path = context.path("discovery", "nmap_raw.txt")
        raw_path.write_text(result.stdout + result.stderr, encoding="utf-8")

        discovery = DiscoveryResult(target=context.target)
        discovery.nmap_raw = result.stdout

        port_111 = bool(re.search(r"111/tcp\s+open", result.stdout, re.IGNORECASE))
        port_2049 = bool(re.search(r"2049/tcp\s+open", result.stdout, re.IGNORECASE))
        discovery.port_111_open = port_111
        discovery.port_2049_open = port_2049
        discovery.nfs_detected = port_111 or port_2049

        parsed = {
            "target": context.target,
            "port_111_open": discovery.port_111_open,
            "port_2049_open": discovery.port_2049_open,
            "nfs_detected": discovery.nfs_detected,
        }
        context.path("discovery", "nmap_parsed.json").write_text(
            json.dumps(parsed, indent=2), encoding="utf-8"
        )

        context.discovery = discovery
