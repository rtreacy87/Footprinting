from __future__ import annotations

from dataclasses import dataclass, field
from typing import Literal


@dataclass
class TlsResult:
    port: int
    starttls_advertised: bool
    starttls_negotiated: bool
    tls_version: str = ""
    cipher_suite: str = ""
    certificate_cn: str = ""
    errors: list[str] = field(default_factory=list)
    status: Literal["supported", "not_supported", "failed", "not_attempted"] = "not_attempted"
