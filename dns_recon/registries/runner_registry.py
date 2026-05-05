from __future__ import annotations

from ..runners.base import BaseRunner
from ..runners.dig_runner import DigRunner
from ..runners.dnsenum_runner import DnsenumRunner
from ..runners.host_runner import HostRunner
from ..runners.nmap_runner import NmapRunner
from ..runners.nslookup_runner import NslookupRunner

RUNNER_REGISTRY: dict[str, type[BaseRunner]] = {
    "dig": DigRunner,
    "host": HostRunner,
    "nslookup": NslookupRunner,
    "nmap": NmapRunner,
    "dnsenum": DnsenumRunner,
}


def get_runner(tool_name: str, timeout: int = 10) -> BaseRunner:
    cls = RUNNER_REGISTRY.get(tool_name)
    if cls is None:
        raise ValueError(f"Unknown tool: {tool_name!r}. Available: {list(RUNNER_REGISTRY)}")
    return cls(timeout=timeout)
