from __future__ import annotations

from dataclasses import dataclass, field
from typing import Literal


@dataclass
class AgentAction:
    action: str
    rationale: str
    priority: Literal["high", "medium", "low"] = "medium"
    prerequisites: list[str] = field(default_factory=list)
    tool_hint: str = ""


@dataclass
class DoNotRetry:
    check_name: str
    reason: str
    evidence: str = ""
