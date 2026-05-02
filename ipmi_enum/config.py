from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path


class ScanProfile(str, Enum):
    PASSIVE = "passive"
    STANDARD = "standard"
    CREDENTIALED = "credentialed"
    HASH_AUDIT = "hash-audit"
    DEFAULT_CREDENTIAL_AUDIT = "default-credential-audit"


@dataclass
class ScanOptions:
    redact_secrets: bool = True
    include_hashes_in_report: bool = False
    continue_on_success: bool = False
    max_runtime_seconds: int = 600
    rate_limit: float | None = None
    enable_rakp: bool = False
    enable_default_creds: bool = False
    enable_cracking: bool = False
    crack_wordlist: Path | None = None
    crack_mask: str | None = None


@dataclass
class ScanConfig:
    target: str
    output_dir: Path
    profile: ScanProfile = ScanProfile.STANDARD
    credentials: list[tuple[str, str]] = field(default_factory=list)
    username_files: list[Path] = field(default_factory=list)
    password_files: list[Path] = field(default_factory=list)
    options: ScanOptions = field(default_factory=ScanOptions)

    def __post_init__(self) -> None:
        self.output_dir = Path(self.output_dir)
        target_id = self.target.replace("/", "_").replace(":", "_")
        self.target_output_dir = self.output_dir / target_id
        self._setup_dirs()

    def _setup_dirs(self) -> None:
        for sub in ("raw", "parsed", "hashes", "markdown"):
            (self.target_output_dir / sub).mkdir(parents=True, exist_ok=True)
