from __future__ import annotations

import re
from dataclasses import dataclass, field

from .base import BaseParser


@dataclass
class NmapPortEntry:
    port: int
    protocol: str
    state: str
    service: str
    version: str = ""


@dataclass
class NmapScanResult:
    raw: str
    open_ports: list[NmapPortEntry] = field(default_factory=list)


class NmapParser(BaseParser):
    """
    Parse nmap -sV text output to extract open TCP port entries.

    Handles lines like:
        25/tcp   open  smtp     Postfix smtpd
        465/tcp  closed smtps
    """

    _PORT_RE = re.compile(
        r"^(\d+)/(tcp|udp)\s+(open\S*)\s+(\S+)\s*(.*)"
    )

    def parse(self, raw: str) -> NmapScanResult:
        result = NmapScanResult(raw=raw)
        for line in raw.splitlines():
            line = line.strip()
            m = self._PORT_RE.match(line)
            if m:
                state = m.group(3)
                if "open" in state:
                    result.open_ports.append(
                        NmapPortEntry(
                            port=int(m.group(1)),
                            protocol=m.group(2),
                            state=state,
                            service=m.group(4),
                            version=m.group(5).strip(),
                        )
                    )
        return result
