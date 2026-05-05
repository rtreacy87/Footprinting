from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

from .target import Target


@dataclass
class ScanContext:
    target: Target
    output_root: Path
    wordlist: Path | None
    from_address: str
    to_address: str
    safe_mode: bool
    timeout: int
    verbose: bool
    skip_relay: bool
    skip_spoofing: bool
    skip_user_enum: bool
    open_ports: list[int] = field(default_factory=list)

    @property
    def target_dir(self) -> Path:
        return self.output_root / self.target.ip
