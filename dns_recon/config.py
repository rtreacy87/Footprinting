from __future__ import annotations

from dataclasses import dataclass, field
from typing import Literal

ScanMode = Literal["passive", "active", "full"]


@dataclass
class DnsReconConfig:
    domain: str
    dns_server: str | None = None
    ip_range: str | None = None
    wordlist: str | None = None
    mode: ScanMode = "full"
    output_root: str = "dns_recon_output"
    timeout: int = 10
    threads: int = 10
    tools: list[str] = field(default_factory=lambda: ["dig", "host", "nslookup"])
    safe: bool = False
    verbose: bool = False
    bruteforce_limit: int = 5000
    skip_subdomain_brute: bool = False
    skip_nmap: bool = False
