from __future__ import annotations

import json
import logging

from ..models.agent_action import AgentAction
from ..models.finding import Finding
from ..models.result import CheckResult
from ..models.scan_context import ScanContext

logger = logging.getLogger(__name__)

_SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}


class AttackPathAnalyzer:
    """
    Synthesize all findings into prioritized attack paths and next actions.
    """

    def analyze(
        self,
        context: ScanContext,
        results: list[CheckResult],
        all_findings: list[Finding],
    ) -> list[AgentAction]:
        actions: list[AgentAction] = []

        # Sort findings by severity
        sorted_findings = sorted(
            all_findings,
            key=lambda f: _SEVERITY_ORDER.get(f.severity, 99),
        )

        for finding in sorted_findings:
            if finding.category == "open_relay" and finding.severity == "critical":
                actions.append(
                    AgentAction(
                        action="Exploit open relay for phishing or spam",
                        rationale=(
                            "Server accepts external→external relay. "
                            "Attacker can send mail as any address."
                        ),
                        priority="high",
                        prerequisites=["open relay confirmed"],
                        tool_hint="swaks --to victim@target.com --from spoof@trusted.com --server <target>",
                    )
                )

            elif finding.category == "user_enumeration" and finding.severity in ("high", "medium"):
                if "confirmed" in finding.description.lower() or "valid" in finding.description.lower():
                    actions.append(
                        AgentAction(
                            action="Use enumerated usernames for credential brute-force",
                            rationale="Valid usernames identified; combine with password spraying.",
                            priority="high",
                            prerequisites=["confirmed user list"],
                            tool_hint="hydra -L users.txt -P wordlist.txt smtp://<target>",
                        )
                    )

            elif finding.category == "authentication" and "weak" in finding.title.lower():
                actions.append(
                    AgentAction(
                        action="Intercept plaintext AUTH credentials via MitM",
                        rationale="AUTH PLAIN/LOGIN transmitted without TLS.",
                        priority="medium",
                        prerequisites=["network position for MitM"],
                        tool_hint="Wireshark / Bettercap on network segment",
                    )
                )

            elif finding.category == "spoofing" and "accepted" in finding.title.lower():
                actions.append(
                    AgentAction(
                        action="Send phishing email with spoofed internal sender",
                        rationale="Server accepts forged MAIL FROM without SPF/DMARC enforcement.",
                        priority="high",
                        prerequisites=["spoofing accepted on MAIL FROM"],
                        tool_hint="swaks --from admin@target.com --to victim@target.com --server <target>",
                    )
                )

        # If no open ports
        if not context.open_ports:
            actions.append(
                AgentAction(
                    action="Verify SMTP is running on non-standard ports",
                    rationale="No SMTP ports detected on standard ports.",
                    priority="low",
                    tool_hint="nmap -Pn -p- --open -T4 <target>",
                )
            )

        # Write attack paths
        out_dir = context.target_dir / "agent_inputs"
        out_dir.mkdir(parents=True, exist_ok=True)
        out_path = out_dir / "attack_paths.json"
        out_path.write_text(
            json.dumps(
                [
                    {
                        "action": a.action,
                        "rationale": a.rationale,
                        "priority": a.priority,
                        "prerequisites": a.prerequisites,
                        "tool_hint": a.tool_hint,
                    }
                    for a in actions
                ],
                indent=2,
            ),
            encoding="utf-8",
        )

        logger.info("[attack_path_analyzer] Generated %d attack paths", len(actions))
        return actions
