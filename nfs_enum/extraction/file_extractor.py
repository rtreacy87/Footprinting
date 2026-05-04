from __future__ import annotations

import json
import re
import subprocess
import tempfile
from pathlib import Path

from ..context import ScanContext
from ..models import ExtractionResult, SensitiveFile

_SENSITIVE_PATTERNS = [
    (re.compile(r"id_rsa|id_ed25519|id_ecdsa|\.pem", re.IGNORECASE), "ssh_key"),
    (re.compile(r"password|passwd|shadow|\.htpasswd|credentials", re.IGNORECASE), "credential"),
    (re.compile(r"\.conf|\.cfg|\.ini|\.env|config\.", re.IGNORECASE), "config"),
    (re.compile(r"flag\.txt|flag$", re.IGNORECASE), "flag"),
]


class FileExtractor:
    def run(self, context: ScanContext, mount_point: str | None = None) -> None:
        extraction = ExtractionResult()

        if mount_point is None:
            context.path("data_extraction", "file_tree.txt").write_text(
                "No mount available for extraction\n", encoding="utf-8"
            )
            context.extraction = extraction
            return

        tree = self._build_tree(mount_point)
        extraction.file_tree = tree
        context.path("data_extraction", "file_tree.txt").write_text(tree, encoding="utf-8")

        sensitive = self._find_sensitive(Path(mount_point), context.config.options.max_file_size_bytes)
        extraction.sensitive_files = sensitive

        context.path("data_extraction", "sensitive_files.json").write_text(
            json.dumps(
                [{"path": f.path, "category": f.category, "preview": f.content_preview} for f in sensitive],
                indent=2,
            ),
            encoding="utf-8",
        )

        credentials = [
            {"path": f.path, "preview": f.content_preview}
            for f in sensitive if f.category == "credential"
        ]
        context.path("data_extraction", "credentials.json").write_text(
            json.dumps(credentials, indent=2), encoding="utf-8"
        )

        context.extraction = extraction

    def _build_tree(self, mount_point: str) -> str:
        try:
            result = subprocess.run(
                ["find", mount_point, "-maxdepth", "5"],
                capture_output=True, text=True, timeout=30
            )
            return result.stdout
        except Exception as e:
            return f"find failed: {e}"

    def _find_sensitive(self, base: Path, max_size: int) -> list[SensitiveFile]:
        found: list[SensitiveFile] = []
        try:
            for fpath in base.rglob("*"):
                if not fpath.is_file():
                    continue
                name = fpath.name
                for pattern, category in _SENSITIVE_PATTERNS:
                    if pattern.search(name):
                        preview: str | None = None
                        try:
                            if fpath.stat().st_size <= max_size:
                                preview = fpath.read_text(encoding="utf-8", errors="replace")[:512]
                        except Exception:
                            pass
                        found.append(SensitiveFile(
                            path=str(fpath),
                            category=category,
                            content_preview=preview,
                        ))
                        break
        except Exception:
            pass
        return found
