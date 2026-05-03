from __future__ import annotations

import uuid

from ..context import ScanContext
from ..core.enums import Confidence, TestStatus
from ..core.errors import CommandTimeoutError
from ..core.runner import CommandRunner
from ..models import Credential, Evidence, TestResult
from ..tools.smbmap_adapter import SmbMapAdapter
from ..parsers.smbmap_parsers import SmbMapPermissionParser
from .base_test import BaseTest
from .test_registry import register_test


def _gen_evid() -> str:
    return f"EVID-{str(uuid.uuid4())[:8].upper()}"


@register_test
class AnonymousWriteCheckTest(BaseTest):
    """PERM-001: Check for anonymous write access to any share."""

    test_id = "PERM-001"
    name = "Anonymous Write Check"
    category = "permissions"
    tool = "smbmap"
    expected_secure_result = "No anonymous write access"

    def run(self, context: ScanContext) -> TestResult:
        runner = CommandRunner(context.output_base)
        adapter = SmbMapAdapter()
        spec = adapter.build_anonymous_scan_command(context.target)
        raw_path = context.output_base / "raw" / "smbmap" / "perm001_anon_write.txt"

        try:
            result = runner.run(spec, stdout_path=raw_path)
        except CommandTimeoutError as exc:
            return self._make_inconclusive_result(str(exc))

        context.command_results.append(result)
        evid = _gen_evid()
        ev = Evidence(
            evidence_id=evid,
            source_tool="smbmap",
            raw_path=str(raw_path),
            summary="Anonymous write check via smbmap",
            confidence=Confidence.HIGH.value,
        )
        context.add_evidence(ev)

        parser = SmbMapPermissionParser()
        parsed = parser.parse(result.stdout)
        permission_map: dict = parsed[0] if parsed else {}
        writable = [name for name, perms in permission_map.items() if perms.get("writable")]

        if writable:
            return TestResult(
                test_id=self.test_id,
                name=self.name,
                category=self.category,
                tool=self.tool,
                command=result.command,
                status=TestStatus.PASSED_VULNERABLE.value,
                evidence_ids=[evid],
                confidence=Confidence.HIGH.value,
                notes=f"Anonymous write access confirmed on: {', '.join(writable)}",
                expected_secure_result=self.expected_secure_result,
                actual_result=f"Writable shares: {', '.join(writable)}",
            )

        return TestResult(
            test_id=self.test_id,
            name=self.name,
            category=self.category,
            tool=self.tool,
            command=result.command,
            status=TestStatus.FAILED_SECURE.value,
            evidence_ids=[evid],
            confidence=Confidence.HIGH.value,
            notes="No anonymous write access detected.",
            expected_secure_result=self.expected_secure_result,
            actual_result="No writable shares",
        )


@register_test
class AuthenticatedWriteCheckTest(BaseTest):
    """PERM-002: Check for write access with provided credentials."""

    test_id = "PERM-002"
    name = "Authenticated Write Check"
    category = "permissions"
    tool = "smbmap"
    expected_secure_result = "No unexpected write access with credentials"

    def run(self, context: ScanContext) -> TestResult:
        if not context.config.credentials:
            return self._make_inconclusive_result(
                "No credentials provided — skipping PERM-002"
            )

        runner = CommandRunner(context.output_base)
        adapter = SmbMapAdapter()
        username, password = context.config.credentials[0]
        cred = Credential(username=username, password=password, domain=context.config.domain)
        spec = adapter.build_authenticated_scan_command(context.target, cred)
        raw_path = context.output_base / "raw" / "smbmap" / "perm002_auth_write.txt"

        try:
            result = runner.run(spec, stdout_path=raw_path)
        except CommandTimeoutError as exc:
            return self._make_inconclusive_result(str(exc))

        context.command_results.append(result)
        evid = _gen_evid()
        ev = Evidence(
            evidence_id=evid,
            source_tool="smbmap",
            raw_path=str(raw_path),
            summary=f"Authenticated write check for '{username}'",
            confidence=Confidence.HIGH.value,
        )
        context.add_evidence(ev)

        parser = SmbMapPermissionParser()
        parsed = parser.parse(result.stdout)
        permission_map: dict = parsed[0] if parsed else {}
        writable = [name for name, perms in permission_map.items() if perms.get("writable")]

        if writable:
            return TestResult(
                test_id=self.test_id,
                name=self.name,
                category=self.category,
                tool=self.tool,
                command=result.command,
                status=TestStatus.PASSED_VULNERABLE.value,
                evidence_ids=[evid],
                confidence=Confidence.HIGH.value,
                notes=f"Write access confirmed for '{username}' on: {', '.join(writable)}",
                expected_secure_result=self.expected_secure_result,
                actual_result=f"Writable: {', '.join(writable)}",
            )

        return TestResult(
            test_id=self.test_id,
            name=self.name,
            category=self.category,
            tool=self.tool,
            command=result.command,
            status=TestStatus.FAILED_SECURE.value,
            evidence_ids=[evid],
            confidence=Confidence.HIGH.value,
            notes=f"No write access detected for '{username}'.",
            expected_secure_result=self.expected_secure_result,
            actual_result="No writable shares",
        )


@register_test
class WorldReadableSensitiveFileTest(BaseTest):
    """PERM-003: Check for world-readable sensitive files in accessible shares."""

    test_id = "PERM-003"
    name = "World-Readable Sensitive File Check"
    category = "permissions"
    tool = "smbclient"
    expected_secure_result = "No sensitive files world-readable"

    def run(self, context: ScanContext) -> TestResult:
        # This test evaluates file_findings already collected by the orchestrator
        if not context.file_findings:
            return self._make_inconclusive_result(
                "No file findings available — run file classification phase first"
            )

        high_risk = [f for f in context.file_findings if f.risk_score >= 7]
        evids = []
        for ff in high_risk:
            evids.extend(ff.evidence_ids)
        evids = list(dict.fromkeys(evids))  # deduplicate, preserve order

        if high_risk:
            paths = [f.path for f in high_risk]
            return TestResult(
                test_id=self.test_id,
                name=self.name,
                category=self.category,
                tool=self.tool,
                command="file classification of recursive listing",
                status=TestStatus.PASSED_VULNERABLE.value,
                evidence_ids=evids,
                confidence=Confidence.HIGH.value,
                notes=f"{len(high_risk)} high-risk files accessible: {'; '.join(paths[:5])}",
                expected_secure_result=self.expected_secure_result,
                actual_result=f"{len(high_risk)} sensitive files found",
            )

        return TestResult(
            test_id=self.test_id,
            name=self.name,
            category=self.category,
            tool=self.tool,
            command="file classification of recursive listing",
            status=TestStatus.FAILED_SECURE.value,
            evidence_ids=[],
            confidence=Confidence.MEDIUM.value,
            notes="No high-risk sensitive files found in accessible shares.",
            expected_secure_result=self.expected_secure_result,
            actual_result="No sensitive files found",
        )
