from __future__ import annotations

from dataclasses import dataclass
from typing import Literal


@dataclass
class SmtpUser:
    username: str
    method: Literal["VRFY", "EXPN", "RCPT_TO"]
    response_code: int
    response_text: str
    status: Literal["confirmed", "rejected", "ambiguous", "blocked", "unreliable"]
    port: int
    is_canary: bool = False
