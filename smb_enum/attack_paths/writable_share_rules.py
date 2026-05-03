from __future__ import annotations

import uuid

from ..context import ScanContext
from ..core.enums import Confidence
from ..core.enums import TestStatus
from ..models import AttackPath, BlockedPath
from .rule import AttackPathRule
from .rule_registry import register_rule


def _gen_path_id(prefix: str) -> str:
    return f"{prefix}-{str(uuid.uuid4())[:8].upper()}"


@register_rule
class WritableShareAttackRule(AttackPathRule):
    """Fire an AttackPath when at least one writable share is detected.

    Fire a BlockedPath when write access was specifically tested and denied.
    """

    def evaluate(self, context: ScanContext) -> AttackPath | BlockedPath | None:
        writable = context.get_writable_shares()

        if writable:
            share_names = [s.name for s in writable]
            evids: list[str] = []
            share003 = context.get_test_result("SHARE-003")
            if share003:
                evids = share003.evidence_ids

            return AttackPath(
                path_id=_gen_path_id("PATH-WRITE"),
                title="Writable SMB share detected",
                description=(
                    f"The following SMB shares allow write access: {', '.join(share_names)}. "
                    "This may allow payload staging, script replacement, or data tampering."
                ),
                required_conditions=[
                    "At least one SMB share is writable",
                ],
                evidence_ids=evids,
                confidence=Confidence.HIGH.value,
                impact=(
                    "Potential staging point for payloads, modification of scripts or "
                    "executables, or data tampering depending on how the share is consumed."
                ),
                next_steps=[
                    "Review writable share contents for scripts and executables",
                    "Identify scheduled tasks or services that consume share contents",
                    "Upload a test file to confirm write access",
                    "Determine whether uploaded files can be executed by users or services",
                ],
            )

        # Check if write was specifically tested and denied
        share003 = context.get_test_result("SHARE-003")
        if share003 and share003.status == TestStatus.FAILED_SECURE.value:
            return BlockedPath(
                path_id=_gen_path_id("BLOCKED-WRITE"),
                title="Anonymous SMB write access blocked",
                blocked_by=["CTRL-SMB-SHARE-002"],
                evidence_ids=share003.evidence_ids,
                confidence=Confidence.HIGH.value,
                reason="Anonymous write access was denied on all tested shares.",
            )

        return None
