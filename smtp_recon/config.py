from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class SmtpReconConfig:
    target: str
    domain: str = ""
    ports: list[int] = field(default_factory=lambda: [25, 465, 587, 2525])
    wordlist: str | None = None
    from_address: str = "test@test.local"
    to_address: str = "test@test.local"
    safe_mode: bool = True
    skip_relay: bool = False
    skip_spoofing: bool = False
    skip_user_enum: bool = False
    timeout: int = 30
    output_root: str = "smtp_recon"
    verbose: bool = False
