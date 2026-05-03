from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path


class ScanProfile(str, Enum):
    SAFE = "safe"
    STANDARD = "standard"
    FULL = "full"
    CUSTOM = "custom"


@dataclass
class ScanOptions:
    timeout_seconds: int = 120
    max_depth: int = 5
    safe_mode: bool = True
    aggressive: bool = False
    redact_secrets: bool = True
    enable_file_classification: bool = True
    enable_user_enum: bool = True
    enable_attack_paths: bool = True


@dataclass
class ScanConfig:
    target: str
    output_dir: Path
    profile: ScanProfile = ScanProfile.STANDARD
    domain: str | None = None
    credentials: list[tuple[str, str]] = field(default_factory=list)
    options: ScanOptions = field(default_factory=ScanOptions)
    custom_tests: list[str] = field(default_factory=list)

    def __post_init__(self) -> None:
        self.output_dir = Path(self.output_dir)
        target_id = self.target.replace("/", "_").replace(":", "_").replace(".", "_")
        self.output_base = self.output_dir / f"smb_enum_{target_id}"
        self._setup_dirs()

    def _setup_dirs(self) -> None:
        subdirs = [
            "metadata",
            "tests",
            "authentication",
            "shares",
            "shares/share_tree",
            "users",
            "security",
            "validation",
            "attack_paths",
            "raw/nmap",
            "raw/smbclient",
            "raw/smbmap",
            "raw/enum4linux",
            "raw/rpcclient",
            "raw/crackmapexec",
            "raw/impacket",
            "summaries",
        ]
        for sub in subdirs:
            (self.output_base / sub).mkdir(parents=True, exist_ok=True)
