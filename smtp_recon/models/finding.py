from __future__ import annotations

from dataclasses import dataclass, field
from typing import Literal


@dataclass
class Finding:
    title: str
    severity: Literal["info", "low", "medium", "high", "critical"]
    category: str
    description: str
    evidence: str = ""
    remediation: str = ""
    tags: list[str] = field(default_factory=list)
    port: int = 0
