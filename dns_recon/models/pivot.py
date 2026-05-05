from __future__ import annotations

from dataclasses import dataclass
from typing import Literal

PivotType = Literal["smtp", "web", "vpn", "cloud", "internal", "other"]


@dataclass
class Pivot:
    hostname: str
    pivot_type: PivotType
    source: str
    recommended_module: str
    ip: str | None = None
    notes: str = ""

    def to_dict(self) -> dict:
        return {
            "hostname": self.hostname,
            "pivot_type": self.pivot_type,
            "source": self.source,
            "recommended_module": self.recommended_module,
            "ip": self.ip,
            "notes": self.notes,
        }
