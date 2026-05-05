from __future__ import annotations

import json
import logging

from ..models.finding import Finding
from ..models.result import CheckResult
from ..models.scan_context import ScanContext

logger = logging.getLogger(__name__)


class RelayAnalyzer:
    """
    Consolidate open relay and spoofing test results into findings.
    """

    def analyze(self, context: ScanContext, results: list[CheckResult]) -> list[Finding]:
        findings: list[Finding] = []
        norm_dir = context.target_dir / "normalized"

        relay_file = norm_dir / "relay_tests.json"
        spoof_file = norm_dir / "spoofing_tests.json"

        relay_stats = {"total": 0, "accepted": 0, "open_relay": False}

        if relay_file.exists():
            try:
                tests = json.loads(relay_file.read_text(encoding="utf-8"))
                for t in tests:
                    relay_stats["total"] += 1
                    if t.get("accepted"):
                        relay_stats["accepted"] += 1
                    if t.get("scenario") == "external->external" and t.get("accepted"):
                        relay_stats["open_relay"] = True
            except Exception as exc:
                logger.warning("[relay_analyzer] Failed to read relay tests: %s", exc)

        spoof_stats = {"total": 0, "accepted": 0}
        if spoof_file.exists():
            try:
                tests = json.loads(spoof_file.read_text(encoding="utf-8"))
                for t in tests:
                    spoof_stats["total"] += 1
                    if t.get("accepted"):
                        spoof_stats["accepted"] += 1
            except Exception as exc:
                logger.warning("[relay_analyzer] Failed to read spoof tests: %s", exc)

        # Summary finding
        if relay_stats["total"] > 0 or spoof_stats["total"] > 0:
            relay_summary = (
                f"Relay: {relay_stats['accepted']}/{relay_stats['total']} accepted. "
                f"Spoofing: {spoof_stats['accepted']}/{spoof_stats['total']} MAIL FROM accepted."
            )
            if relay_stats["open_relay"]:
                findings.append(
                    Finding(
                        title="Open relay confirmed",
                        severity="critical",
                        category="open_relay",
                        description=relay_summary,
                        tags=["open_relay", "spam", "phishing"],
                    )
                )
            elif relay_stats["accepted"] > 0:
                findings.append(
                    Finding(
                        title="Partial relay misconfiguration",
                        severity="high",
                        category="open_relay",
                        description=relay_summary,
                    )
                )

        return findings
