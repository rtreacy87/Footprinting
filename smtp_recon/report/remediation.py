from __future__ import annotations

import json
import logging

from ..models.finding import Finding
from ..models.scan_context import ScanContext

logger = logging.getLogger(__name__)

_REMEDIATION_MAP = {
    "open_relay": (
        "critical",
        "Restrict mail relay to authenticated users. "
        "Set mynetworks to trusted IP ranges only. "
        "Require SASL authentication for relaying.",
    ),
    "user_enumeration": (
        "high",
        "Disable VRFY and EXPN commands. "
        "Configure identical responses for valid and invalid RCPT TO addresses.",
    ),
    "authentication": (
        "high",
        "Enforce STARTTLS before advertising AUTH. "
        "Disable AUTH PLAIN and AUTH LOGIN on unencrypted connections. "
        "Use strong mechanisms: CRAM-MD5, GSSAPI, or OAUTH2.",
    ),
    "tls": (
        "medium",
        "Enable STARTTLS on ports 25 and 587. "
        "Use TLS 1.2+ with strong cipher suites. "
        "Obtain a valid certificate from a trusted CA.",
    ),
    "spoofing": (
        "high",
        "Implement SPF records to restrict authorized senders. "
        "Configure DKIM signing. "
        "Enforce DMARC policy (p=reject). "
        "Configure the server to reject spoofed sender addresses.",
    ),
    "information_disclosure": (
        "low",
        "Suppress server version information from banners. "
        "Set smtpd_banner to a generic string.",
    ),
}


def build_remediation_plan(
    context: ScanContext,
    all_findings: list[Finding],
) -> dict:
    """Build a prioritized remediation plan from findings."""
    categories_found = {f.category for f in all_findings}
    plan = []

    for category, (priority, guidance) in _REMEDIATION_MAP.items():
        if category in categories_found:
            specific_findings = [f.title for f in all_findings if f.category == category]
            plan.append(
                {
                    "category": category,
                    "priority": priority,
                    "guidance": guidance,
                    "related_findings": specific_findings,
                }
            )

    # Sort by priority
    priority_order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
    plan.sort(key=lambda x: priority_order.get(x["priority"], 99))

    out_path = context.target_dir / "report" / "remediation_plan.json"
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps(plan, indent=2), encoding="utf-8")
    logger.info("[remediation] Written to %s", out_path)
    return {"remediation_plan": plan}
