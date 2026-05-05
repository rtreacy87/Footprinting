from __future__ import annotations

import json
import logging

from ..models.agent_action import DoNotRetry
from ..models.result import CheckResult
from ..models.scan_context import ScanContext

logger = logging.getLogger(__name__)

# Response codes that definitively indicate a feature is unavailable
_BLOCKED_CODES = {502, 500, 503}


class DoNotRetryBuilder:
    """
    Build the do_not_retry.json list for agent consumption.
    Identifies checks that are definitively blocked or unreliable.
    """

    def build(
        self,
        context: ScanContext,
        results: list[CheckResult],
    ) -> list[DoNotRetry]:
        do_not_retry: list[DoNotRetry] = []

        for result in results:
            # Check for canary false positive findings
            for finding in result.findings:
                if "canary false positive" in finding.title.lower() or "unreliable" in finding.title.lower():
                    do_not_retry.append(
                        DoNotRetry(
                            check_name=result.name,
                            reason="Canary false positive detected — results unreliable",
                            evidence=finding.evidence,
                        )
                    )

            # Check for fully blocked commands
            for finding in result.findings:
                if "blocked" in finding.title.lower() and "command" in finding.title.lower():
                    do_not_retry.append(
                        DoNotRetry(
                            check_name=result.name,
                            reason=f"Command blocked: {finding.description}",
                            evidence=finding.evidence,
                        )
                    )

        # Write to agent_inputs
        out_dir = context.target_dir / "agent_inputs"
        out_dir.mkdir(parents=True, exist_ok=True)
        out_path = out_dir / "do_not_retry.json"
        out_path.write_text(
            json.dumps(
                [
                    {
                        "check_name": d.check_name,
                        "reason": d.reason,
                        "evidence": d.evidence,
                    }
                    for d in do_not_retry
                ],
                indent=2,
            ),
            encoding="utf-8",
        )
        logger.info("[do_not_retry_builder] Wrote %d entries to %s", len(do_not_retry), out_path)
        return do_not_retry
