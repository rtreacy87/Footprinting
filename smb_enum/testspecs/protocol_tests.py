from __future__ import annotations

import uuid

from ..context import ScanContext
from ..core.enums import Confidence, TestStatus
from ..core.errors import CommandTimeoutError
from ..core.runner import CommandRunner
from ..models import Evidence, ProtocolSecurityInfo, TestResult
from ..parsers.nmap_parsers import NmapVersionParser, NmapSmbScriptParser
from ..tools.nmap_adapter import NmapAdapter
from .base_test import BaseTest
from .test_registry import register_test


def _gen_evid() -> str:
    return f"EVID-{str(uuid.uuid4())[:8].upper()}"


@register_test
class SmbVersionDetectionTest(BaseTest):
    """PROTO-001: Detect SMB version via nmap service scan."""

    test_id = "PROTO-001"
    name = "SMB Version Detection"
    category = "protocol"
    tool = "nmap"
    expected_secure_result = "SMBv1 not present"

    def run(self, context: ScanContext) -> TestResult:
        runner = CommandRunner(context.output_base)
        adapter = NmapAdapter()
        spec = adapter.build_version_scan_command(context.target)
        raw_path = context.output_base / "raw" / "nmap" / "proto001_version.txt"

        try:
            result = runner.run(spec, stdout_path=raw_path)
        except CommandTimeoutError as exc:
            return self._make_inconclusive_result(str(exc))

        context.command_results.append(result)
        evid = _gen_evid()
        ev = Evidence(
            evidence_id=evid,
            source_tool="nmap",
            raw_path=str(raw_path),
            summary="nmap SMB version scan",
            confidence=Confidence.HIGH.value,
        )
        context.add_evidence(ev)

        parser = NmapVersionParser()
        banners = parser.parse(result.stdout)
        if banners:
            context.smb_version_banner = banners[0]

        if not result.stdout.strip():
            return self._make_inconclusive_result(
                "nmap produced no output",
                evidence_ids=[evid],
                command=result.command,
            )

        return TestResult(
            test_id=self.test_id,
            name=self.name,
            category=self.category,
            tool=self.tool,
            command=result.command,
            status=TestStatus.PASSED_VULNERABLE.value if banners else TestStatus.INCONCLUSIVE.value,
            evidence_ids=[evid],
            confidence=Confidence.HIGH.value if banners else Confidence.LOW.value,
            notes=f"Version banner: {banners[0]}" if banners else "No version banner extracted",
            expected_secure_result=self.expected_secure_result,
            actual_result=banners[0] if banners else "No version detected",
        )


@register_test
class SmbSigningStatusTest(BaseTest):
    """PROTO-002: Check SMB signing status via nmap scripts."""

    test_id = "PROTO-002"
    name = "SMB Signing Status"
    category = "protocol"
    tool = "nmap"
    expected_secure_result = "SMB signing required"

    def run(self, context: ScanContext) -> TestResult:
        runner = CommandRunner(context.output_base)
        adapter = NmapAdapter()
        spec = adapter.build_smb_scripts_command(context.target)
        raw_path = context.output_base / "raw" / "nmap" / "proto002_smb_scripts.txt"

        try:
            result = runner.run(spec, stdout_path=raw_path)
        except CommandTimeoutError as exc:
            return self._make_inconclusive_result(str(exc))

        context.command_results.append(result)
        evid = _gen_evid()
        ev = Evidence(
            evidence_id=evid,
            source_tool="nmap",
            raw_path=str(raw_path),
            summary="nmap SMB script scan (signing/protocols)",
            confidence=Confidence.HIGH.value,
        )
        context.add_evidence(ev)

        parser = NmapSmbScriptParser()
        info = parser.parse(result.stdout)

        # Merge into context.protocol_info
        if context.protocol_info is None:
            context.protocol_info = ProtocolSecurityInfo()
        if info:
            proto = info[0]
            if proto.signing_enabled is not None:
                context.protocol_info.signing_enabled = proto.signing_enabled
            if proto.signing_required is not None:
                context.protocol_info.signing_required = proto.signing_required
            if proto.smb_versions:
                context.protocol_info.smb_versions = proto.smb_versions
            if proto.dialect:
                context.protocol_info.dialect = proto.dialect

        signing_required = context.protocol_info.signing_required if context.protocol_info else None

        if signing_required is True:
            status = TestStatus.FAILED_SECURE.value
            confidence = Confidence.HIGH.value
            notes = "SMB signing is required."
            actual = "signing required"
        elif signing_required is False:
            status = TestStatus.PASSED_VULNERABLE.value
            confidence = Confidence.HIGH.value
            notes = "SMB signing is not required — relay attacks may be possible."
            actual = "signing not required"
        else:
            status = TestStatus.INCONCLUSIVE.value
            confidence = Confidence.LOW.value
            notes = "Could not determine SMB signing requirement from nmap output."
            actual = "unknown"

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
class Smb1EnabledTest(BaseTest):
    """PROTO-003: Check whether SMBv1 is enabled."""

    test_id = "PROTO-003"
    name = "SMBv1 Enabled Check"
    category = "protocol"
    tool = "nmap"
    expected_secure_result = "SMBv1 disabled"

    def run(self, context: ScanContext) -> TestResult:
        runner = CommandRunner(context.output_base)
        adapter = NmapAdapter()
        spec = adapter.build_smb1_check_command(context.target)
        raw_path = context.output_base / "raw" / "nmap" / "proto003_smb1.txt"

        try:
            result = runner.run(spec, stdout_path=raw_path)
        except CommandTimeoutError as exc:
            return self._make_inconclusive_result(str(exc))

        context.command_results.append(result)
        evid = _gen_evid()
        ev = Evidence(
            evidence_id=evid,
            source_tool="nmap",
            raw_path=str(raw_path),
            summary="nmap SMBv1 probe",
            confidence=Confidence.HIGH.value,
        )
        context.add_evidence(ev)

        parser = NmapSmbScriptParser()
        info = parser.parse(result.stdout)

        smb1_enabled: bool | None = None
        if info:
            smb1_enabled = info[0].smb1_enabled

        # Fallback: look for SMBv1 / NT LM 0.12 in raw output
        if smb1_enabled is None:
            if "SMBv1" in result.stdout or "NT LM 0.12" in result.stdout:
                smb1_enabled = True
            elif "SMB 2" in result.stdout or "SMB 3" in result.stdout:
                smb1_enabled = False

        if context.protocol_info is None:
            context.protocol_info = ProtocolSecurityInfo()
        if smb1_enabled is not None:
            context.protocol_info.smb1_enabled = smb1_enabled

        if smb1_enabled is True:
            status = TestStatus.PASSED_VULNERABLE.value
            confidence = Confidence.HIGH.value
            notes = "SMBv1 is enabled — high risk (EternalBlue, etc.)."
            actual = "SMBv1 enabled"
        elif smb1_enabled is False:
            status = TestStatus.FAILED_SECURE.value
            confidence = Confidence.HIGH.value
            notes = "SMBv1 is disabled."
            actual = "SMBv1 disabled"
        else:
            status = TestStatus.INCONCLUSIVE.value
            confidence = Confidence.LOW.value
            notes = "Could not determine SMBv1 status."
            actual = "unknown"

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
class RelayRiskCheckTest(BaseTest):
    """PROTO-004: Evaluate SMB relay risk based on signing status."""

    test_id = "PROTO-004"
    name = "SMB Relay Risk Check"
    category = "protocol"
    tool = "nmap"
    expected_secure_result = "SMB signing required — relay not viable"

    def run(self, context: ScanContext) -> TestResult:
        # This test derives its result from existing protocol_info collected in PROTO-002
        proto = context.protocol_info

        if proto is None:
            return self._make_inconclusive_result(
                "Protocol info not available — run PROTO-002 first"
            )

        # Gather evidence IDs from signing test
        signing_test = context.get_test_result("PROTO-002")
        evids = signing_test.evidence_ids if signing_test else []

        if proto.signing_required is False:
            return TestResult(
                test_id=self.test_id,
                name=self.name,
                category=self.category,
                tool=self.tool,
                command="derived from PROTO-002",
                status=TestStatus.PASSED_VULNERABLE.value,
                evidence_ids=evids,
                confidence=Confidence.HIGH.value,
                notes=(
                    "SMB signing is not required. Relay attacks (NTLM relay, "
                    "SMBRelay) may be viable if an authentication source exists."
                ),
                expected_secure_result=self.expected_secure_result,
                actual_result="Relay risk: HIGH",
            )

        if proto.signing_required is True:
            return TestResult(
                test_id=self.test_id,
                name=self.name,
                category=self.category,
                tool=self.tool,
                command="derived from PROTO-002",
                status=TestStatus.FAILED_SECURE.value,
                evidence_ids=evids,
                confidence=Confidence.HIGH.value,
                notes="SMB signing is required — relay attacks blocked.",
                expected_secure_result=self.expected_secure_result,
                actual_result="Relay risk: LOW",
            )

        return self._make_inconclusive_result(
            "Signing requirement unknown — relay risk cannot be determined",
            evidence_ids=evids,
            command="derived from PROTO-002",
        )
