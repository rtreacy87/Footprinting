from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class AuthMethod:
    method: str
    port: int
    requires_tls: bool = False
    advertised_before_tls: bool = False
    advertised_after_tls: bool = False
    notes: str = ""
