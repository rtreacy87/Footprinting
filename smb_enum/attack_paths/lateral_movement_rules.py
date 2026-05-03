from __future__ import annotations

import uuid

from ..context import ScanContext
from ..core.enums import Confidence, TestStatus
from ..models import AttackPath, BlockedPath
from .rule import AttackPathRule
from .rule_registry import register_rule


def _gen_path_id(prefix: str) -> str:
    return f"{prefix}-{str(uuid.uuid4())[:8].upper()}"


@register_rule
class LateralMovementWithCredentialsRule(AttackPathRule):
    """Fire when valid credentials have been confirmed via AUTH-003."""

    def evaluate(self, context: ScanContext) -> AttackPath | BlockedPath | None:
        auth003 = context.get_test_result("AUTH-003")
        if auth003 is None:
            return None

        if auth003.status != TestStatus.PASSED_VULNERABLE.value:
            return None

        evids = auth003.evidence_ids
        username = context.config.credentials[0][0] if context.config.credentials else "unknown"

        return AttackPath(
            path_id=_gen_path_id("PATH-LATERAL"),
            title=f"Lateral movement possible with valid credentials for '{username}'",
            description=(
                f"Credentials for '{username}' were validated successfully against the "
                "SMB service. These credentials may be reusable against additional services "
                "or hosts in the environment."
            ),
            required_conditions=[
                "Valid credentials confirmed via SMB authentication",
            ],
            evidence_ids=evids,
            confidence=Confidence.HIGH.value,
            impact=(
                "Potential access to additional services (WinRM, RDP, MSSQL, LDAP) "
                "and lateral movement to other hosts sharing the same credentials."
            ),
            next_steps=[
                "Spray credentials against other SMB hosts in the network range",
                "Test credentials against WinRM (port 5985/5986)",
                "Test credentials against RDP (port 3389)",
                "Test credentials against LDAP / Active Directory",
                "Check for local admin rights that enable pass-the-hash",
            ],
        )
