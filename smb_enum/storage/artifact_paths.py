from __future__ import annotations

from pathlib import Path


class ArtifactPaths:
    """Resolves output paths relative to the scan output base directory."""

    def __init__(self, output_base: Path) -> None:
        self._base = Path(output_base)

    @property
    def base(self) -> Path:
        return self._base

    def raw_tool_path(self, tool: str, filename: str) -> Path:
        return self._base / "raw" / tool / filename

    def test_output_path(self, test_id: str) -> Path:
        return self._base / "tests" / f"{test_id.lower()}.json"

    def share_tree_path(self, share_name: str) -> Path:
        return self._base / "shares" / "share_tree" / share_name

    def share_file_index_path(self, share_name: str) -> Path:
        return self.share_tree_path(share_name) / "file_index.json"

    def share_raw_listing_path(self, share_name: str) -> Path:
        return self.share_tree_path(share_name) / "raw_listing.txt"

    def share_sensitive_files_path(self, share_name: str) -> Path:
        return self.share_tree_path(share_name) / "sensitive_files.json"

    def metadata_path(self, filename: str) -> Path:
        return self._base / "metadata" / filename

    def users_path(self, filename: str) -> Path:
        return self._base / "users" / filename

    def security_path(self, filename: str) -> Path:
        return self._base / "security" / filename

    def validation_path(self, filename: str) -> Path:
        return self._base / "validation" / filename

    def attack_paths_path(self, filename: str) -> Path:
        return self._base / "attack_paths" / filename

    def summaries_path(self, filename: str) -> Path:
        return self._base / "summaries" / filename

    def authentication_path(self, filename: str) -> Path:
        return self._base / "authentication" / filename
