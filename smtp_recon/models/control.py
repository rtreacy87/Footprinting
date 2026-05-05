from __future__ import annotations

from dataclasses import dataclass, field
from typing import Literal


@dataclass
class Control:
    name: str
    control_type: Literal["block", "rate_limit", "auth_required", "tls_required", "unknown"]
    port: int
    description: str = ""
    evidence: str = ""
    bypass_hints: list[str] = field(default_factory=list)
