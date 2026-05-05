from __future__ import annotations

import json
import logging
from pathlib import Path

from ..models.finding import Finding
from ..models.result import CheckResult
from ..models.scan_context import ScanContext

logger = logging.getLogger(__name__)


def build_executive_summary(
    context: ScanContext,
    results: list[CheckResult],
    all_findings: list[Finding],
) -> dict:
    """Return a dict suitable for JSON serialization."""
    critical = [f for f in all_findings if f.severity == "critical"]
    high = [f for f in all_findings if f.severity == "high"]

    risk_level = "low"
    if critical:
        risk_level = "critical"
    elif high:
        risk_level = "high"
    elif any(f.severity == "medium" for f in all_findings):
        risk_level = "medium"

    summary = {
        "target": context.target.ip,
        "domain": context.target.domain,
        "open_ports": context.open_ports,
        "overall_risk": risk_level,
        "total_findings": len(all_findings),
        "critical_findings": len(critical),
        "high_findings": len(high),
        "key_issues": [f.title for f in (critical + high)[:5]],
        "checks_run": len(results),
        "checks_passed": len([r for r in results if r.status == "success"]),
        "checks_failed": len([r for r in results if r.status == "failed"]),
        "checks_skipped": len([r for r in results if r.status == "skipped"]),
    }

    out_path = context.target_dir / "report" / "executive_summary.json"
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps(summary, indent=2), encoding="utf-8")
    logger.info("[executive_summary] Written to %s", out_path)
    return summary
