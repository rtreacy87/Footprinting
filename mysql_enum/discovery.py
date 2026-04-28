"""TCP reachability and service discovery."""

from __future__ import annotations

import socket
import time
from pathlib import Path

from .config import TargetConfig
from .utils.nmap import run_nmap_mysql


class DiscoveryResult:
    def __init__(
        self,
        reachable: bool,
        latency_ms: float | None,
        error: str | None,
        nmap: dict,
    ) -> None:
        self.reachable = reachable
        self.latency_ms = latency_ms
        self.error = error
        self.nmap = nmap

    def to_dict(self) -> dict:
        return {
            "reachable": self.reachable,
            "latency_ms": self.latency_ms,
            "error": self.error,
            "nmap": self.nmap,
        }


def check_tcp(target: str, port: int, timeout: int = 10) -> tuple[bool, float | None, str | None]:
    start = time.monotonic()
    try:
        with socket.create_connection((target, port), timeout=timeout):
            latency = (time.monotonic() - start) * 1000
            return True, round(latency, 2), None
    except (ConnectionRefusedError, OSError) as e:
        return False, None, str(e)


def discover(config: TargetConfig, run_nmap: bool = True) -> DiscoveryResult:
    reachable, latency, error = check_tcp(config.target, config.port, config.timeout_seconds)

    nmap_result: dict = {}
    if run_nmap and reachable:
        raw_dir = config.target_dir / "raw" / "nmap_mysql"
        nmap_result = run_nmap_mysql(config.target, config.port, raw_dir)

    return DiscoveryResult(
        reachable=reachable,
        latency_ms=latency,
        error=error,
        nmap=nmap_result,
    )
