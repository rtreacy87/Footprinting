from __future__ import annotations

from dataclasses import dataclass, field
from typing import Literal

AttemptStatus = Literal["success", "failure", "refused", "timeout", "error", "unknown", "partial"]


@dataclass
class Attempt:
    category: str
    name: str
    target: str
    status: AttemptStatus
    detail: str = ""
    raw_output: str = ""
    records_found: list[dict] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "category": self.category,
            "name": self.name,
            "target": self.target,
            "status": self.status,
            "detail": self.detail,
            "records_found": self.records_found,
        }
