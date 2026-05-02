from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path


@dataclass
class CrackProfile:
    name: str
    mode: str = "dictionary"
    wordlist: Path | None = None
    mask: str | None = None
    charset: str | None = None
    max_runtime_seconds: int = 600


CRACK_PROFILES = {
    "quick": CrackProfile(
        name="quick",
        mode="dictionary",
        wordlist=Path("/usr/share/wordlists/fasttrack.txt"),
        max_runtime_seconds=120,
    ),
    "rockyou": CrackProfile(
        name="rockyou",
        mode="dictionary",
        wordlist=Path("/usr/share/wordlists/rockyou.txt"),
        max_runtime_seconds=600,
    ),
    "hp_ilo": CrackProfile(
        name="hp_ilo",
        mode="mask",
        mask="?1?1?1?1?1?1?1?1",
        charset="?d?u",
        max_runtime_seconds=300,
    ),
}
