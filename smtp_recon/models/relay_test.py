from __future__ import annotations

from dataclasses import dataclass
from typing import Literal


@dataclass
class RelayTest:
    port: int
    mail_from: str
    rcpt_to: str
    scenario: str  # e.g. "external->external"
    mail_from_code: int
    rcpt_to_code: int
    accepted: bool
    safe_mode: bool
    notes: str = ""
