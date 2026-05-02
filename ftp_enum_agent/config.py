from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path


@dataclass
class ScanConfig:
    target: str
    port: int = 21
    output_dir: Path = field(default_factory=lambda: Path("output/ftp"))
    protocol: str = "ftp"

    # Auth
    username: str | None = None
    password: str | None = None
    anonymous_credentials: list[tuple[str, str]] = field(default_factory=lambda: [
        ("anonymous", "anonymous@"),
        ("anonymous", ""),
        ("ftp", "ftp"),
    ])

    # Download limits
    max_file_size_mb: float = 10.0
    max_total_download_mb: float = 100.0

    # Feature flags (safe by default)
    check_upload: bool = False
    cleanup_upload_test: bool = False
    safe_mode: bool = True
    unsafe_write_tests: bool = False
    mirror: bool = False

    # Timing
    timeout: float = 10.0
    idle_gap: float = 0.6

    def __post_init__(self) -> None:
        self.output_dir = Path(self.output_dir)
        target_id = self.target.replace("/", "_").replace(":", "_")
        self.target_dir = self.output_dir / target_id
        for sub in ("raw", "downloads", "normalized", "reports"):
            (self.target_dir / sub).mkdir(parents=True, exist_ok=True)

    def raw_path(self, filename: str) -> Path:
        return self.target_dir / "raw" / filename

    def downloads_path(self, *parts: str) -> Path:
        return self.target_dir / "downloads" / Path(*parts)

    def normalized_path(self, filename: str) -> Path:
        return self.target_dir / "normalized" / filename

    def reports_path(self, filename: str) -> Path:
        return self.target_dir / "reports" / filename
