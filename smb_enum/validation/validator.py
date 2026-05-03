from __future__ import annotations

from ..context import ScanContext
from ..core.enums import ControlStatus, Confidence, TestStatus
from ..models import ControlAssessment
from .control import CONTROL_DEFINITIONS


class ControlValidator:
    """Maps test results from ScanContext into ControlAssessment objects.

    Rule: never mark a control as PASSED unless the relevant test actually
    ran and produced usable evidence.
    """

    def assess_all(self, context: ScanContext) -> list[ControlAssessment]:
        assessments: list[ControlAssessment] = []
        for control_id in CONTROL_DEFINITIONS:
            assessment = self._assess_control(control_id, context)
            assessments.append(assessment)
        return assessments

    # ------------------------------------------------------------------
    # Per-control assessment logic
    # ------------------------------------------------------------------

    def _assess_control(self, control_id: str, context: ScanContext) -> ControlAssessment:
        defn = CONTROL_DEFINITIONS[control_id]
        name = defn["name"]

        method = getattr(self, f"_assess_{control_id.replace('-', '_').lower()}", None)
        if method is None:
            return ControlAssessment(
                control_id=control_id,
                name=name,
                status=ControlStatus.NOT_TESTED.value,
                confidence=Confidence.UNKNOWN.value,
                reason="No validator implemented for this control.",
            )
        return method(context, name)

    def _assess_ctrl_smb_auth_001(self, context: ScanContext, name: str) -> ControlAssessment:
        result = context.get_test_result("AUTH-001")
        if result is None:
            return self._not_tested(
                "CTRL-SMB-AUTH-001", name, "AUTH-001 was not run."
            )
        if result.status == TestStatus.ERROR.value or result.status == TestStatus.INCONCLUSIVE.value:
            return self._inconclusive(
                "CTRL-SMB-AUTH-001", name, result.evidence_ids,
                result.notes or "Test was inconclusive.",
            )
        if result.status == TestStatus.FAILED_SECURE.value:
            return ControlAssessment(
                control_id="CTRL-SMB-AUTH-001",
                name=name,
                status=ControlStatus.PASSED.value,
                evidence_ids=result.evidence_ids,
                confidence=result.confidence,
                reason="Anonymous share listing was denied.",
            )
        if result.status == TestStatus.PASSED_VULNERABLE.value:
            return ControlAssessment(
                control_id="CTRL-SMB-AUTH-001",
                name=name,
                status=ControlStatus.FAILED.value,
                evidence_ids=result.evidence_ids,
                confidence=result.confidence,
                reason="Anonymous share listing succeeded — anonymous access is enabled.",
            )
        return self._inconclusive("CTRL-SMB-AUTH-001", name, result.evidence_ids, result.notes or "")

    def _assess_ctrl_smb_share_001(self, context: ScanContext, name: str) -> ControlAssessment:
        result = context.get_test_result("SHARE-002")
        if result is None:
            return self._not_tested("CTRL-SMB-SHARE-001", name, "SHARE-002 was not run.")
        if result.status in (TestStatus.ERROR.value, TestStatus.INCONCLUSIVE.value):
            return self._inconclusive("CTRL-SMB-SHARE-001", name, result.evidence_ids, result.notes or "")
        if result.status == TestStatus.FAILED_SECURE.value:
            return ControlAssessment(
                control_id="CTRL-SMB-SHARE-001",
                name=name,
                status=ControlStatus.PASSED.value,
                evidence_ids=result.evidence_ids,
                confidence=result.confidence,
                reason="No shares were anonymously readable.",
            )
        return ControlAssessment(
            control_id="CTRL-SMB-SHARE-001",
            name=name,
            status=ControlStatus.FAILED.value,
            evidence_ids=result.evidence_ids,
            confidence=result.confidence,
            reason=result.notes or "Anonymous readable shares detected.",
        )

    def _assess_ctrl_smb_share_002(self, context: ScanContext, name: str) -> ControlAssessment:
        result = context.get_test_result("SHARE-003")
        if result is None:
            return self._not_tested("CTRL-SMB-SHARE-002", name, "SHARE-003 was not run.")
        if result.status in (TestStatus.ERROR.value, TestStatus.INCONCLUSIVE.value):
            return self._inconclusive("CTRL-SMB-SHARE-002", name, result.evidence_ids, result.notes or "")
        if result.status == TestStatus.FAILED_SECURE.value:
            return ControlAssessment(
                control_id="CTRL-SMB-SHARE-002",
                name=name,
                status=ControlStatus.PASSED.value,
                evidence_ids=result.evidence_ids,
                confidence=result.confidence,
                reason="No shares were anonymously writable.",
            )
        return ControlAssessment(
            control_id="CTRL-SMB-SHARE-002",
            name=name,
            status=ControlStatus.FAILED.value,
            evidence_ids=result.evidence_ids,
            confidence=result.confidence,
            reason=result.notes or "Anonymous writable shares detected.",
        )

    def _assess_ctrl_smb_proto_001(self, context: ScanContext, name: str) -> ControlAssessment:
        result = context.get_test_result("PROTO-002")
        if result is None:
            return self._not_tested("CTRL-SMB-PROTO-001", name, "PROTO-002 was not run.")
        if result.status in (TestStatus.ERROR.value, TestStatus.INCONCLUSIVE.value):
            return self._inconclusive("CTRL-SMB-PROTO-001", name, result.evidence_ids, result.notes or "")
        if result.status == TestStatus.FAILED_SECURE.value:
            return ControlAssessment(
                control_id="CTRL-SMB-PROTO-001",
                name=name,
                status=ControlStatus.PASSED.value,
                evidence_ids=result.evidence_ids,
                confidence=result.confidence,
                reason="SMB signing is required.",
            )
        return ControlAssessment(
            control_id="CTRL-SMB-PROTO-001",
            name=name,
            status=ControlStatus.FAILED.value,
            evidence_ids=result.evidence_ids,
            confidence=result.confidence,
            reason="SMB signing is not required — relay attacks may be viable.",
        )

    def _assess_ctrl_smb_proto_002(self, context: ScanContext, name: str) -> ControlAssessment:
        result = context.get_test_result("PROTO-003")
        if result is None:
            return self._not_tested("CTRL-SMB-PROTO-002", name, "PROTO-003 was not run.")
        if result.status in (TestStatus.ERROR.value, TestStatus.INCONCLUSIVE.value):
            return self._inconclusive("CTRL-SMB-PROTO-002", name, result.evidence_ids, result.notes or "")
        if result.status == TestStatus.FAILED_SECURE.value:
            return ControlAssessment(
                control_id="CTRL-SMB-PROTO-002",
                name=name,
                status=ControlStatus.PASSED.value,
                evidence_ids=result.evidence_ids,
                confidence=result.confidence,
                reason="SMBv1 is disabled.",
            )
        return ControlAssessment(
            control_id="CTRL-SMB-PROTO-002",
            name=name,
            status=ControlStatus.FAILED.value,
            evidence_ids=result.evidence_ids,
            confidence=result.confidence,
            reason="SMBv1 is enabled — exposure to legacy exploits.",
        )

    def _assess_ctrl_smb_data_001(self, context: ScanContext, name: str) -> ControlAssessment:
        cred_findings = [f for f in context.file_findings if f.file_type == "credential"]
        evids = []
        for ff in cred_findings:
            evids.extend(ff.evidence_ids)
        evids = list(dict.fromkeys(evids))

        if not context.file_findings and not context.get_accessible_shares():
            return self._not_tested(
                "CTRL-SMB-DATA-001", name, "No file classification was performed."
            )

        if cred_findings:
            return ControlAssessment(
                control_id="CTRL-SMB-DATA-001",
                name=name,
                status=ControlStatus.FAILED.value,
                evidence_ids=evids,
                confidence=Confidence.HIGH.value,
                reason=f"{len(cred_findings)} credential file(s) found in accessible shares.",
            )

        return ControlAssessment(
            control_id="CTRL-SMB-DATA-001",
            name=name,
            status=ControlStatus.PASSED.value,
            evidence_ids=[],
            confidence=Confidence.MEDIUM.value,
            reason="No credential files found in accessible shares.",
        )

    def _assess_ctrl_smb_data_002(self, context: ScanContext, name: str) -> ControlAssessment:
        backup_findings = [f for f in context.file_findings if f.file_type == "backup"]
        evids = []
        for ff in backup_findings:
            evids.extend(ff.evidence_ids)
        evids = list(dict.fromkeys(evids))

        if not context.file_findings and not context.get_accessible_shares():
            return self._not_tested(
                "CTRL-SMB-DATA-002", name, "No file classification was performed."
            )

        if backup_findings:
            return ControlAssessment(
                control_id="CTRL-SMB-DATA-002",
                name=name,
                status=ControlStatus.FAILED.value,
                evidence_ids=evids,
                confidence=Confidence.HIGH.value,
                reason=f"{len(backup_findings)} backup/archive file(s) found in accessible shares.",
            )

        return ControlAssessment(
            control_id="CTRL-SMB-DATA-002",
            name=name,
            status=ControlStatus.PASSED.value,
            evidence_ids=[],
            confidence=Confidence.MEDIUM.value,
            reason="No backup files found in accessible shares.",
        )

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def _not_tested(
        self, control_id: str, name: str, reason: str
    ) -> ControlAssessment:
        return ControlAssessment(
            control_id=control_id,
            name=name,
            status=ControlStatus.NOT_TESTED.value,
            evidence_ids=[],
            confidence=Confidence.UNKNOWN.value,
            reason=reason,
        )

    def _inconclusive(
        self,
        control_id: str,
        name: str,
        evidence_ids: list[str],
        reason: str,
    ) -> ControlAssessment:
        return ControlAssessment(
            control_id=control_id,
            name=name,
            status=ControlStatus.INCONCLUSIVE.value,
            evidence_ids=evidence_ids,
            confidence=Confidence.LOW.value,
            reason=reason,
        )
