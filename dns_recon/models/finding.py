from __future__ import annotations

from dataclasses import dataclass, field
from typing import Literal

Severity = Literal["critical", "high", "medium", "low", "informational", "contextual"]


@dataclass
class Finding:
    title: str
    severity: Severity
    description: str
    evidence: list[str] = field(default_factory=list)
    recommendation: str = ""

    def to_dict(self) -> dict:
        return {
            "title": self.title,
            "severity": self.severity,
            "description": self.description,
            "evidence": self.evidence,
            "recommendation": self.recommendation,
        }
