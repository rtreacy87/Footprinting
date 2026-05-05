from __future__ import annotations

import json
import logging

from ..models.agent_action import AgentAction
from ..models.result import CheckResult
from ..models.scan_context import ScanContext

logger = logging.getLogger(__name__)


class NextActionBuilder:
    """
    Build the next_actions.json file for agent consumption.
    Aggregates attack paths + context-driven suggestions.
    """

    def build(
        self,
        context: ScanContext,
        results: list[CheckResult],
        attack_paths: list[AgentAction],
    ) -> list[dict]:
        actions = []

        # Add attack paths
        for ap in attack_paths:
            actions.append(
                {
                    "action": ap.action,
                    "rationale": ap.rationale,
                    "priority": ap.priority,
                    "prerequisites": ap.prerequisites,
                    "tool_hint": ap.tool_hint,
                    "source": "attack_path_analyzer",
                }
            )

        # Context-driven suggestions based on what was found
        if context.open_ports:
            if 587 in context.open_ports:
                actions.append(
                    {
                        "action": "Test SMTP AUTH on port 587 with common credentials",
                        "rationale": "Port 587 (submission) typically requires authentication.",
                        "priority": "medium",
                        "prerequisites": ["port 587 open"],
                        "tool_hint": "hydra -l admin -P rockyou.txt smtp://<target>:587",
                        "source": "port_context",
                    }
                )
            if 465 in context.open_ports:
                actions.append(
                    {
                        "action": "Enumerate capabilities on SMTPS port 465",
                        "rationale": "Port 465 uses implicit TLS; may expose different auth methods.",
                        "priority": "medium",
                        "prerequisites": ["port 465 open"],
                        "tool_hint": "openssl s_client -connect <target>:465",
                        "source": "port_context",
                    }
                )

        # Failures worth retrying
        failed = [r for r in results if r.status == "failed" and r.errors]
        if failed:
            actions.append(
                {
                    "action": "Retry failed checks with increased timeout",
                    "rationale": f"{len(failed)} check(s) failed — may be timeout or connectivity.",
                    "priority": "low",
                    "prerequisites": [],
                    "tool_hint": "Re-run with --timeout 60",
                    "source": "failure_analysis",
                }
            )

        # Write to agent_inputs
        out_dir = context.target_dir / "agent_inputs"
        out_dir.mkdir(parents=True, exist_ok=True)
        out_path = out_dir / "next_actions.json"
        out_path.write_text(json.dumps(actions, indent=2), encoding="utf-8")
        logger.info("[next_action_builder] Wrote %d actions to %s", len(actions), out_path)
        return actions
