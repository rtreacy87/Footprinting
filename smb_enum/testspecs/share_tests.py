from __future__ import annotations

import uuid
from pathlib import Path

from ..context import ScanContext
from ..core.enums import Confidence, TestStatus
from ..core.errors import CommandTimeoutError
from ..core.runner import CommandRunner
from ..models import Credential, Evidence, Share, TestResult
from ..parsers.smbclient_parsers import SmbClientShareListParser
from ..parsers.smbmap_parsers import SmbMapPermissionParser
from ..tools.smbclient_adapter import SmbClientAdapter
from ..tools.smbmap_adapter import SmbMapAdapter
from .base_test import BaseTest
from .test_registry import register_test


def _gen_evid() -> str:
    return f"EVID-{str(uuid.uuid4())[:8].upper()}"


@register_test
class ShareEnumerationTest(BaseTest):
    """SHARE-001: Enumerate visible shares via smbclient."""

    test_id = "SHARE-001"
    name = "Enumerate Visible Shares"
    category = "shares"
    tool = "smbclient"
    expected_secure_result = "Only expected shares visible"

    def run(self, context: ScanContext) -> TestResult:
        runner = CommandRunner(context.output_base)
        adapter = SmbClientAdapter()
        spec = adapter.build_list_shares_command(context.target)
        raw_path = context.output_base / "raw" / "smbclient" / "share001_list.txt"

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
            summary="smbclient anonymous share listing",
            confidence=Confidence.HIGH.value,
        )
        context.add_evidence(ev)

        parser = SmbClientShareListParser()
        shares = parser.parse(result.stdout)

        # Merge into context — avoid duplicates by name
        existing_names = {s.name for s in context.shares}
        for share in shares:
            if share.name not in existing_names:
                context.shares.append(share)
                existing_names.add(share.name)

        if "NT_STATUS_ACCESS_DENIED" in (result.stdout + result.stderr):
            return TestResult(
                test_id=self.test_id,
                name=self.name,
                category=self.category,
                tool=self.tool,
                command=result.command,
                status=TestStatus.FAILED_SECURE.value,
                evidence_ids=[evid],
                confidence=Confidence.HIGH.value,
                notes="Anonymous share listing was denied.",
                expected_secure_result=self.expected_secure_result,
                actual_result="NT_STATUS_ACCESS_DENIED",
            )

        share_names = [s.name for s in shares]
        return TestResult(
            test_id=self.test_id,
            name=self.name,
            category=self.category,
            tool=self.tool,
            command=result.command,
            status=TestStatus.PASSED_VULNERABLE.value if shares else TestStatus.INCONCLUSIVE.value,
            evidence_ids=[evid],
            confidence=Confidence.HIGH.value if shares else Confidence.LOW.value,
            notes=f"Found {len(shares)} shares: {', '.join(share_names)}",
            expected_secure_result=self.expected_secure_result,
            actual_result=f"{len(shares)} shares visible",
        )


@register_test
class ReadableSharesTest(BaseTest):
    """SHARE-002: Determine readable shares via smbmap (anonymous)."""

    test_id = "SHARE-002"
    name = "Determine Readable Shares"
    category = "shares"
    tool = "smbmap"
    expected_secure_result = "No shares readable anonymously"

    def run(self, context: ScanContext) -> TestResult:
        runner = CommandRunner(context.output_base)
        adapter = SmbMapAdapter()
        spec = adapter.build_anonymous_scan_command(context.target)
        raw_path = context.output_base / "raw" / "smbmap" / "share002_anon_perms.txt"

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
            summary="smbmap anonymous share permission scan",
            confidence=Confidence.HIGH.value,
        )
        context.add_evidence(ev)

        parser = SmbMapPermissionParser()
        parsed = parser.parse(result.stdout)
        permission_map: dict = parsed[0] if parsed else {}

        readable: list[str] = []
        for share_name, perms in permission_map.items():
            # Find or create share in context
            share = next((s for s in context.shares if s.name == share_name), None)
            if share is None:
                share = Share(name=share_name)
                context.shares.append(share)
            if perms.get("readable"):
                share.readable = True
                share.anonymous_access = True
                readable.append(share_name)
            else:
                if share.readable is None:
                    share.readable = False

        if readable:
            status = TestStatus.PASSED_VULNERABLE.value
            confidence = Confidence.HIGH.value
            notes = f"Anonymous read access to: {', '.join(readable)}"
            actual = f"Readable: {', '.join(readable)}"
        else:
            status = TestStatus.FAILED_SECURE.value
            confidence = Confidence.HIGH.value
            notes = "No shares readable anonymously."
            actual = "No readable shares"

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
class WritableSharesTest(BaseTest):
    """SHARE-003: Determine writable shares via smbmap (anonymous)."""

    test_id = "SHARE-003"
    name = "Determine Writable Shares"
    category = "shares"
    tool = "smbmap"
    expected_secure_result = "No shares writable anonymously"

    def run(self, context: ScanContext) -> TestResult:
        runner = CommandRunner(context.output_base)
        adapter = SmbMapAdapter()
        spec = adapter.build_anonymous_scan_command(context.target)
        raw_path = context.output_base / "raw" / "smbmap" / "share003_anon_write.txt"

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
            summary="smbmap anonymous write permission scan",
            confidence=Confidence.HIGH.value,
        )
        context.add_evidence(ev)

        parser = SmbMapPermissionParser()
        parsed = parser.parse(result.stdout)
        permission_map: dict = parsed[0] if parsed else {}

        writable: list[str] = []
        for share_name, perms in permission_map.items():
            share = next((s for s in context.shares if s.name == share_name), None)
            if share is None:
                share = Share(name=share_name)
                context.shares.append(share)
            if perms.get("writable"):
                share.writable = True
                writable.append(share_name)
            else:
                if share.writable is None:
                    share.writable = False

        if writable:
            status = TestStatus.PASSED_VULNERABLE.value
            confidence = Confidence.HIGH.value
            notes = f"Anonymous write access to: {', '.join(writable)}"
            actual = f"Writable: {', '.join(writable)}"
        else:
            status = TestStatus.FAILED_SECURE.value
            confidence = Confidence.HIGH.value
            notes = "No shares writable anonymously."
            actual = "No writable shares"

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
class RecursiveShareListingTest(BaseTest):
    """SHARE-004: Recursively list files in accessible shares."""

    test_id = "SHARE-004"
    name = "Recursive Share Listing"
    category = "shares"
    tool = "smbclient"
    expected_secure_result = "No readable shares accessible"

    def run(self, context: ScanContext) -> TestResult:
        accessible = context.get_accessible_shares()
        if not accessible:
            return self._make_inconclusive_result(
                "No accessible shares to recurse — run SHARE-002 first"
            )

        runner = CommandRunner(context.output_base)
        adapter = SmbClientAdapter()
        all_evids: list[str] = []
        total_files = 0

        for share in accessible:
            spec = adapter.build_recursive_list_command(context.target, share.name)
            raw_path = context.output_base / "raw" / "smbclient" / f"share004_{share.name}_recurse.txt"
            try:
                result = runner.run(spec, stdout_path=raw_path)
            except CommandTimeoutError:
                context.skip_step(f"SHARE-004:{share.name}", "Timed out during recursive listing")
                continue

            context.command_results.append(result)
            evid = _gen_evid()
            ev = Evidence(
                evidence_id=evid,
                source_tool="smbclient",
                raw_path=str(raw_path),
                summary=f"Recursive file listing of share '{share.name}'",
                confidence=Confidence.HIGH.value,
            )
            context.add_evidence(ev)
            all_evids.append(evid)
            # Count lines as rough file proxy
            total_files += result.stdout.count("\n")

        if not all_evids:
            return self._make_inconclusive_result("All recursive listing attempts timed out")

        return TestResult(
            test_id=self.test_id,
            name=self.name,
            category=self.category,
            tool=self.tool,
            command="smbclient //<target>/<share> -N -c recurse;ls",
            status=TestStatus.PASSED_VULNERABLE.value,
            evidence_ids=all_evids,
            confidence=Confidence.HIGH.value,
            notes=f"Recursed {len(all_evids)} shares.",
            expected_secure_result=self.expected_secure_result,
            actual_result=f"Listed files in {len(all_evids)} shares",
        )
