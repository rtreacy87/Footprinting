from __future__ import annotations

import dataclasses
import json
import logging

from ..models.finding import Finding
from ..models.result import CheckResult
from ..models.scan_context import ScanContext

logger = logging.getLogger(__name__)


def build_technical_summary(
    context: ScanContext,
    results: list[CheckResult],
    all_findings: list[Finding],
) -> dict:
    """Build a detailed technical summary grouped by category."""
    by_category: dict[str, list[dict]] = {}
    for finding in all_findings:
        by_category.setdefault(finding.category, []).append(
            dataclasses.asdict(finding)
        )

    per_port: dict[int, list[str]] = {}
    for finding in all_findings:
        if finding.port:
            per_port.setdefault(finding.port, []).append(finding.title)

    summary = {
        "target": context.target.ip,
        "open_ports": context.open_ports,
        "findings_by_category": by_category,
        "findings_by_port": per_port,
        "check_details": [dataclasses.asdict(r) for r in results],
    }

    out_path = context.target_dir / "report" / "technical_summary.json"
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps(summary, indent=2), encoding="utf-8")
    logger.info("[technical_summary] Written to %s", out_path)
    return summary
