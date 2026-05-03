from __future__ import annotations

import uuid

from ..context import ScanContext
from ..core.enums import Confidence
from ..models import AttackPath, BlockedPath
from .rule import AttackPathRule
from .rule_registry import register_rule


def _gen_path_id(prefix: str) -> str:
    return f"{prefix}-{str(uuid.uuid4())[:8].upper()}"


@register_rule
class CredentialExposureRule(AttackPathRule):
    """Fire when credential-type files are found with medium+ confidence."""

    def evaluate(self, context: ScanContext) -> AttackPath | BlockedPath | None:
        cred_findings = [
            f for f in context.file_findings
            if f.file_type == "credential" and f.risk_score >= 7
        ]

        if not cred_findings:
            return None

        evids: list[str] = []
        for ff in cred_findings:
            evids.extend(ff.evidence_ids)
        evids = list(dict.fromkeys(evids))

        paths_desc = "; ".join(f.path for f in cred_findings[:5])

        return AttackPath(
            path_id=_gen_path_id("PATH-CRED"),
            title="Credential files exposed via SMB share",
            description=(
                f"{len(cred_findings)} potential credential file(s) found in accessible SMB "
                f"shares: {paths_desc}. These may contain passwords, private keys, or API tokens."
            ),
            required_conditions=[
                "At least one SMB share is anonymously or credentially readable",
                "Credential-type files present in accessible share",
            ],
            evidence_ids=evids,
            confidence=Confidence.HIGH.value,
            impact=(
                "Extracted credentials may be valid for SMB, WinRM, RDP, MSSQL, LDAP, "
                "or other services. Could enable lateral movement or privilege escalation."
            ),
            next_steps=[
                "Download identified credential files",
                "Extract and validate any credentials found",
                "Test credentials against SMB, WinRM, LDAP, and RDP",
                "Check for password reuse across accounts",
            ],
        )
