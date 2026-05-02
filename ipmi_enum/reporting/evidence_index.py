from __future__ import annotations

import json
from pathlib import Path

from ..context import ScanContext


class EvidenceIndex:
    def write(self, context: ScanContext, output_path: Path | None = None) -> Path:
        path = output_path or (context.output_dir / "evidence_index.json")
        index = {
            "target": context.target,
            "files": [
                {"path": ref, "exists": Path(ref).exists()}
                for ref in context.evidence_refs
            ],
        }
        path.write_text(json.dumps(index, indent=2), encoding="utf-8")
        return path
