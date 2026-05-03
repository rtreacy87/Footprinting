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
class SmbRelayRiskRule(AttackPathRule):
    """Fire when SMB signing is not required — relay attacks may be viable."""

    def evaluate(self, context: ScanContext) -> AttackPath | BlockedPath | None:
        proto = context.protocol_info
        if proto is None:
            return None

        proto002 = context.get_test_result("PROTO-002")
        evids = proto002.evidence_ids if proto002 else []

        if proto.signing_required is False:
            return AttackPath(
                path_id=_gen_path_id("PATH-RELAY"),
                title="SMB relay attack possible — signing not required",
                description=(
                    "The target does not require SMB message signing. An attacker "
                    "positioned on the network could relay captured NTLM authentication "
                    "to gain access to this host or other SMB-enabled systems."
                ),
                required_conditions=[
                    "Network position that allows interception of authentication",
                    "SMB signing not required on target",
                ],
                evidence_ids=evids,
                confidence=Confidence.HIGH.value,
                impact=(
                    "NTLM relay via Responder + ntlmrelayx. Could yield code execution "
                    "or persistent access if relayed to an SMB admin share."
                ),
                next_steps=[
                    "Run Responder to capture NTLM challenge/response",
                    "Use ntlmrelayx to relay to this target",
                    "Check for other signing-disabled hosts to relay between",
                    "Combine with PrinterBug or PetitPotam for forced authentication",
                ],
            )

        if proto.signing_required is True:
            return BlockedPath(
                path_id=_gen_path_id("BLOCKED-RELAY"),
                title="SMB relay attack blocked — signing required",
                blocked_by=["CTRL-SMB-PROTO-001"],
                evidence_ids=evids,
                confidence=Confidence.HIGH.value,
                reason="SMB signing is required on this host, preventing relay attacks.",
            )

        return None
