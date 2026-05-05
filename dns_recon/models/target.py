from __future__ import annotations

from dataclasses import dataclass, field
from typing import Literal

ScanMode = Literal["passive", "active", "full"]


@dataclass
class Target:
    domain: str
    dns_server: str | None = None
    ip_range: str | None = None
    wordlist: str | None = None
    mode: ScanMode = "full"
