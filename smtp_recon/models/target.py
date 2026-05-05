from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class Target:
    ip: str
    domain: str = ""
    ports: list[int] = field(default_factory=lambda: [25, 465, 587, 2525])
