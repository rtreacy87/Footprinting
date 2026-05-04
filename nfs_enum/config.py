from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path

_NFS_SUBDIRS = (
    "discovery",
    "enumeration",
    "access_checks",
    "mount_attempts",
    "data_extraction",
    "permissions",
    "pivoting",
    "vulnerabilities",
    "logs",
    "summary",
)


class ScanProfile(str, Enum):
    DISCOVERY = "discovery"
    STANDARD = "standard"
    FULL = "full"


@dataclass
class ScanOptions:
    redact_secrets: bool = True
    nmap_timeout_seconds: int = 120
    mount_timeout_seconds: int = 30
    max_file_size_bytes: int = 1_048_576
    attempt_mount: bool = True
    attempt_write_check: bool = False


@dataclass
class ScanConfig:
    target: str
    output_dir: Path
    profile: ScanProfile = ScanProfile.STANDARD
    options: ScanOptions = field(default_factory=ScanOptions)

    def __post_init__(self) -> None:
        self.output_dir = Path(self.output_dir)
        target_id = self.target.replace("/", "_").replace(":", "_")
        self.target_output_dir = self.output_dir / target_id
        self._setup_dirs()

    def _setup_dirs(self) -> None:
        for sub in _NFS_SUBDIRS:
            (self.target_output_dir / sub).mkdir(parents=True, exist_ok=True)
