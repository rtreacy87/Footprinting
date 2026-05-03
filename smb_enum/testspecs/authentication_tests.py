from __future__ import annotations

import uuid
from pathlib import Path

from ..context import ScanContext
from ..core.enums import Confidence, TestStatus
from ..core.errors import CommandTimeoutError
from ..core.runner import CommandRunner
from ..models import Credential, Evidence, TestResult
from ..tools.smbclient_adapter import SmbClientAdapter
from ..tools.rpcclient_adapter import RpcClientAdapter
from ..validation.evidence import EvidenceStore
from .base_test import BaseTest
from .test_registry import register_test


def _gen_evid() -> str:
    return f"EVID-{str(uuid.uuid4())[:8].upper()}"


@register_test
class AnonymousShareListingTest(BaseTest):
    """AUTH-001: Try listing shares as an anonymous (null) user via smbclient."""

    test_id = "AUTH-001"
    name = "Anonymous SMB Share Listing"
    category = "authentication"
    tool = "smbclient"
    expected_secure_result = "NT_STATUS_ACCESS_DENIED"

    def run(self, context: ScanContext) -> TestResult:
        runner = CommandRunner(context.output_base)
        adapter = SmbClientAdapter()
        spec = adapter.build_list_shares_command(context.target)

        raw_path = context.output_base / "raw" / "smbclient" / "auth001_anon_list.txt"

        try:
            result = runner.run(spec, stdout_path=raw_path)
        except CommandTimeoutError as exc:
            return self._make_inconclusive_result(str(exc))

        context.command_results.append(result)
        evid = _gen_evid()
        ev = Evidence(
            evidence_id=evid,
            source_tool="smbclient",
            raw_path=str(raw_path),
            summary="Anonymous smbclient share listing",
            confidence=Confidence.HIGH.value,
        )
        context.add_evidence(ev)

        combined = result.stdout + result.stderr
        denied = "NT_STATUS_ACCESS_DENIED" in combined or "NT_STATUS_LOGON_FAILURE" in combined
        connection_refused = "NT_STATUS_CONNECTION_REFUSED" in combined or "NT_STATUS_HOST_UNREACHABLE" in combined

        if connection_refused:
            return self._make_inconclusive_result(
                "Could not connect to target on SMB port",
                evidence_ids=[evid],
                command=result.command,
            )

        if denied:
            status = TestStatus.FAILED_SECURE.value
            actual = "NT_STATUS_ACCESS_DENIED"
            confidence = Confidence.HIGH.value
            notes = "Anonymous share listing was denied."
        elif "Sharename" in result.stdout or "Disk" in result.stdout:
            status = TestStatus.PASSED_VULNERABLE.value
            actual = "Share list returned"
            confidence = Confidence.HIGH.value
            notes = "Anonymous share listing succeeded."
        else:
            status = TestStatus.INCONCLUSIVE.value
            actual = "Ambiguous output"
            confidence = Confidence.LOW.value
            notes = f"Unexpected smbclient output: {combined[:200]}"

        return TestResult(
            test_id=self.test_id,
            name=self.name,
            category=self.category,
            tool=self.tool,
            command=result.command,
            status=status,
            evidence_ids=[evid],
            confidence=confidence,
            notes=notes,
            expected_secure_result=self.expected_secure_result,
            actual_result=actual,
        )


@register_test
class AnonymousIpcAccessTest(BaseTest):
    """AUTH-002: Try a null session via rpcclient to IPC$."""

    test_id = "AUTH-002"
    name = "Anonymous IPC$ Access (Null Session)"
    category = "authentication"
    tool = "rpcclient"
    expected_secure_result = "NT_STATUS_ACCESS_DENIED"

    def run(self, context: ScanContext) -> TestResult:
        runner = CommandRunner(context.output_base)
        adapter = RpcClientAdapter()
        spec = adapter.build_null_session_command(context.target, "srvinfo")

        raw_path = context.output_base / "raw" / "rpcclient" / "auth002_null_session.txt"

        try:
            result = runner.run(spec, stdout_path=raw_path)
        except CommandTimeoutError as exc:
            return self._make_inconclusive_result(str(exc))

        context.command_results.append(result)
        evid = _gen_evid()
        ev = Evidence(
            evidence_id=evid,
            source_tool="rpcclient",
            raw_path=str(raw_path),
            summary="rpcclient null session srvinfo",
            confidence=Confidence.HIGH.value,
        )
        context.add_evidence(ev)

        combined = result.stdout + result.stderr
        denied = "NT_STATUS_ACCESS_DENIED" in combined or "NT_STATUS_LOGON_FAILURE" in combined

        if denied:
            status = TestStatus.FAILED_SECURE.value
            actual = "NT_STATUS_ACCESS_DENIED"
            confidence = Confidence.HIGH.value
            notes = "Null session (IPC$) was denied."
        elif result.return_code == 0 or "Server:" in result.stdout or "OS:" in result.stdout or "domain" in result.stdout.lower():
            status = TestStatus.PASSED_VULNERABLE.value
            actual = "Null session succeeded"
            confidence = Confidence.HIGH.value
            notes = "Null session to IPC$ succeeded — anonymous RPC access allowed."
        else:
            status = TestStatus.INCONCLUSIVE.value
            actual = combined[:200]
            confidence = Confidence.LOW.value
            notes = "Could not determine null session status from output."

        return TestResult(
            test_id=self.test_id,
            name=self.name,
            category=self.category,
            tool=self.tool,
            command=result.command,
            status=status,
            evidence_ids=[evid],
            confidence=confidence,
            notes=notes,
            expected_secure_result=self.expected_secure_result,
            actual_result=actual,
        )


@register_test
class CredentialValidationTest(BaseTest):
    """AUTH-003: Validate provided credentials via smbclient share listing."""

    test_id = "AUTH-003"
    name = "Credential Validation"
    category = "authentication"
    tool = "smbclient"
    expected_secure_result = "Authentication fails with supplied credentials"

    def run(self, context: ScanContext) -> TestResult:
        if not context.config.credentials:
            return self._make_inconclusive_result(
                "No credentials provided — skipping AUTH-003"
            )

        runner = CommandRunner(context.output_base)
        adapter = SmbClientAdapter()

        username, password = context.config.credentials[0]
        cred = Credential(username=username, password=password, domain=context.config.domain)
        spec = adapter.build_list_shares_command(context.target, credential=cred)

        raw_path = context.output_base / "raw" / "smbclient" / "auth003_cred_validation.txt"

        try:
            result = runner.run(spec, stdout_path=raw_path)
        except CommandTimeoutError as exc:
            return self._make_inconclusive_result(str(exc))

        context.command_results.append(result)
        evid = _gen_evid()
        ev = Evidence(
            evidence_id=evid,
            source_tool="smbclient",
            raw_path=str(raw_path),
            summary=f"Credential validation for user '{username}'",
            confidence=Confidence.HIGH.value,
        )
        context.add_evidence(ev)

        combined = result.stdout + result.stderr
        failed = "NT_STATUS_LOGON_FAILURE" in combined or "NT_STATUS_ACCESS_DENIED" in combined

        if failed:
            status = TestStatus.FAILED_SECURE.value
            actual = "Authentication failed"
            confidence = Confidence.HIGH.value
            notes = f"Credentials for '{username}' were rejected."
        elif "Sharename" in result.stdout or "Disk" in result.stdout:
            status = TestStatus.PASSED_VULNERABLE.value
            actual = "Authentication succeeded"
            confidence = Confidence.HIGH.value
            notes = f"Credentials for '{username}' are valid."
        else:
            status = TestStatus.INCONCLUSIVE.value
            actual = combined[:200]
            confidence = Confidence.LOW.value
            notes = "Ambiguous output — could not confirm credential validity."

        return TestResult(
            test_id=self.test_id,
            name=self.name,
            category=self.category,
            tool=self.tool,
            command=result.command,
            status=status,
            evidence_ids=[evid],
            confidence=confidence,
            notes=notes,
            expected_secure_result=self.expected_secure_result,
            actual_result=actual,
        )
