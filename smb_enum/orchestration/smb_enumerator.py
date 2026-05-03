from __future__ import annotations

import logging
import uuid
from pathlib import Path

from ..config import ScanConfig, ScanProfile
from ..context import ScanContext
from ..core.enums import Confidence
from ..core.errors import CommandTimeoutError, SmbEnumError
from ..core.runner import CommandRunner
from ..models import (
    Credential,
    Evidence,
    ProtocolSecurityInfo,
    Share,
    Target,
)
from ..parsers.smbclient_parsers import SmbClientFileListParser
from ..parsers.rpcclient_parsers import (
    RpcClientUserParser,
    RpcClientGroupParser,
    RpcClientDomainParser,
    RpcClientShareInfoParser,
)
from ..tools.smbclient_adapter import SmbClientAdapter
from ..tools.rpcclient_adapter import RpcClientAdapter
from ..classifiers.classifier_registry import CLASSIFIER_REGISTRY
from ..validation.validator import ControlValidator
from ..attack_paths.attack_path import AttackPathEvaluator
from ..reporting.report_registry import REPORTER_REGISTRY

# Import all test modules to trigger @register_test decorators
from ..testspecs import authentication_tests  # noqa: F401
from ..testspecs import share_tests  # noqa: F401
from ..testspecs import permission_tests  # noqa: F401
from ..testspecs import protocol_tests  # noqa: F401
from ..testspecs.test_registry import TEST_REGISTRY

# Import rule registry to trigger @register_rule decorators
from ..attack_paths import rule_registry  # noqa: F401

# Import reporter registry to trigger @register_reporter decorators
from ..reporting import report_registry  # noqa: F401

# Import classifier registry to trigger @register_classifier decorators
from ..classifiers import classifier_registry  # noqa: F401

# Import parser registry to trigger @register_parser decorators
from ..parsers import parser_registry  # noqa: F401

logger = logging.getLogger(__name__)


def _gen_evid() -> str:
    return f"EVID-{str(uuid.uuid4())[:8].upper()}"


class SmbEnumerator:
    """Main orchestrator for SMB enumeration.

    Executes enumeration in sequential phases. The set of phases executed
    depends on ``config.profile``:

    - SAFE: phases 1-4, 8 (no recursive listing, no user enum, no attack paths)
    - STANDARD: phases 1-8 (default)
    - FULL: all phases 1-10
    """

    def __init__(self, config: ScanConfig) -> None:
        self._config = config
        self._runner = CommandRunner(config.output_base)

    def run(self) -> ScanContext:
        context = ScanContext(config=self._config)
        profile = self._config.profile

        logger.info("Starting SMB enumeration for %s (profile=%s)", self._config.target, profile.value)

        # Phase 1: Initialize context
        self._phase_init(context)

        # Phase 2: Protocol discovery
        self._run_phase("Protocol Discovery", self._phase_protocol_discovery, context)

        # Phase 3: Authentication testing
        self._run_phase("Authentication Testing", self._phase_authentication_testing, context)

        # Phase 4: Share enumeration
        self._run_phase("Share Enumeration", self._phase_share_enumeration, context)

        # Phase 5: Recursive file listing (STANDARD/FULL only)
        if profile in (ScanProfile.STANDARD, ScanProfile.FULL):
            self._run_phase("Recursive File Listing", self._phase_recursive_file_listing, context)
        else:
            context.skip_step("Recursive File Listing", f"Skipped for profile {profile.value}")

        # Phase 6: File download for high-risk files (STANDARD/FULL only)
        if profile in (ScanProfile.STANDARD, ScanProfile.FULL):
            self._run_phase("File Download", self._phase_file_download, context)
        else:
            context.skip_step("File Download", f"Skipped for profile {profile.value}")

        # Phase 7: User/group/domain enumeration (STANDARD/FULL only)
        if profile in (ScanProfile.STANDARD, ScanProfile.FULL):
            self._run_phase("User Enumeration", self._phase_user_enum, context)
        else:
            context.skip_step("User Enumeration", f"Skipped for profile {profile.value}")

        # Phase 8: Security validation
        self._run_phase("Security Validation", self._phase_security_validation, context)

        # Phase 9: Attack path generation (FULL only)
        if profile == ScanProfile.FULL:
            self._run_phase("Attack Path Generation", self._phase_attack_paths, context)
        else:
            context.skip_step("Attack Path Generation", f"Skipped for profile {profile.value}")

        # Phase 10: Reporting
        self._run_phase("Reporting", self._phase_reporting, context)

        logger.info("SMB enumeration complete for %s", self._config.target)
        return context

    # ------------------------------------------------------------------
    # Phase implementations
    # ------------------------------------------------------------------

    def _phase_init(self, context: ScanContext) -> None:
        """Phase 1: Build the Target object and populate initial context."""
        context.domain = self._config.domain
        logger.debug("Target initialized: %s", self._config.target)

    def _phase_protocol_discovery(self, context: ScanContext) -> None:
        """Phase 2: Run nmap version + SMB script scans; parse version banner."""
        from ..testspecs.protocol_tests import SmbVersionDetectionTest, SmbSigningStatusTest

        version_test = SmbVersionDetectionTest()
        result = version_test.run(context)
        context.add_test_result(result)

        signing_test = SmbSigningStatusTest()
        result = signing_test.run(context)
        context.add_test_result(result)

        logger.debug(
            "Protocol discovery: banner=%s signing_required=%s",
            context.smb_version_banner,
            context.protocol_info.signing_required if context.protocol_info else None,
        )

    def _phase_authentication_testing(self, context: ScanContext) -> None:
        """Phase 3: Run AUTH-001 and AUTH-002; optionally AUTH-003."""
        for test_id in ("AUTH-001", "AUTH-002", "AUTH-003"):
            test_cls = TEST_REGISTRY.get(test_id)
            if test_cls is None:
                continue
            test = test_cls()
            result = test.run(context)
            context.add_test_result(result)
            logger.debug("Test %s: %s", test_id, result.status)

    def _phase_share_enumeration(self, context: ScanContext) -> None:
        """Phase 4: Run SHARE-001, SHARE-002, SHARE-003."""
        for test_id in ("SHARE-001", "SHARE-002", "SHARE-003"):
            test_cls = TEST_REGISTRY.get(test_id)
            if test_cls is None:
                continue
            test = test_cls()
            result = test.run(context)
            context.add_test_result(result)
            logger.debug("Test %s: %s", test_id, result.status)

    def _phase_recursive_file_listing(self, context: ScanContext) -> None:
        """Phase 5: For each readable share, recurse + classify files."""
        accessible = context.get_accessible_shares()
        if not accessible:
            logger.debug("No accessible shares — skipping recursive listing")
            return

        smbclient = SmbClientAdapter()
        file_parser = SmbClientFileListParser()

        for share in accessible:
            self._recurse_share(context, smbclient, file_parser, share)

    def _recurse_share(
        self,
        context: ScanContext,
        smbclient: SmbClientAdapter,
        file_parser: SmbClientFileListParser,
        share: Share,
    ) -> None:
        """Recursive listing and classification for a single share."""
        cred: Credential | None = None
        if self._config.credentials:
            username, password = self._config.credentials[0]
            cred = Credential(username=username, password=password, domain=self._config.domain)

        spec = smbclient.build_recursive_list_command(
            self._config.target,
            share.name,
            cred,
            timeout=self._config.options.timeout_seconds,
        )
        raw_path = self._config.output_base / "raw" / "smbclient" / f"recurse_{share.name}.txt"

        try:
            result = self._runner.run(spec, stdout_path=raw_path)
        except CommandTimeoutError:
            context.skip_step(f"recursive_listing:{share.name}", "Timed out")
            return

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

        file_metadata_list = file_parser.parse(result.stdout)
        for fm in file_metadata_list:
            fm.share = share.name

        share.file_count = len(file_metadata_list)
        context.file_metadata.extend(file_metadata_list)

        # Save raw listing to share tree
        share_tree_path = self._config.output_base / "shares" / "share_tree" / share.name
        share_tree_path.mkdir(parents=True, exist_ok=True)
        raw_listing_path = share_tree_path / "raw_listing.txt"
        raw_listing_path.write_text(result.stdout, encoding="utf-8")

        # Classify each file
        classifiers = [cls() for cls in CLASSIFIER_REGISTRY.values()]
        for fm in file_metadata_list:
            for classifier in classifiers:
                findings = classifier.classify(fm)
                for ff in findings:
                    ff.evidence_ids.append(evid)
                    context.file_findings.append(ff)

        logger.debug(
            "Share %s: %d files, %d findings",
            share.name,
            len(file_metadata_list),
            len(context.file_findings),
        )

    def _phase_file_download(self, context: ScanContext) -> None:
        """Phase 6: Download high-risk files (risk_score >= 7)."""
        high_risk = [f for f in context.file_findings if f.risk_score >= 7]
        if not high_risk:
            logger.debug("No high-risk files to download")
            return

        smbclient = SmbClientAdapter()
        cred: Credential | None = None
        if self._config.credentials:
            username, password = self._config.credentials[0]
            cred = Credential(username=username, password=password, domain=self._config.domain)

        for ff in high_risk:
            share_name = ff.share
            remote_path = ff.path

            # Store downloaded content under share_tree/<share>/downloads/
            download_dir = (
                self._config.output_base / "shares" / "share_tree" / share_name / "downloads"
            )
            download_dir.mkdir(parents=True, exist_ok=True)
            safe_filename = remote_path.replace("\\", "_").replace("/", "_").lstrip("_")
            local_path = download_dir / safe_filename

            spec = smbclient.build_get_file_command(
                self._config.target,
                share_name,
                remote_path,
                local_path,
                cred,
                timeout=60,
            )

            try:
                result = self._runner.run(spec)
            except CommandTimeoutError:
                context.skip_step(f"file_download:{remote_path}", "Timed out")
                continue

            context.command_results.append(result)

            if local_path.exists():
                try:
                    content = local_path.read_text(encoding="utf-8", errors="replace")
                    context.file_contents[(share_name, remote_path)] = content
                    ff.content_excerpt = content[:500] if content else None
                    logger.debug("Downloaded: %s/%s", share_name, remote_path)
                except Exception as exc:
                    logger.debug("Could not read downloaded file %s: %s", local_path, exc)

    def _phase_user_enum(self, context: ScanContext) -> None:
        """Phase 7: Enumerate users, groups, and domain via rpcclient."""
        rpcclient = RpcClientAdapter()
        target = self._config.target

        # Users
        spec = rpcclient.build_user_enum_command(target)
        raw_path = self._config.output_base / "raw" / "rpcclient" / "users.txt"
        try:
            result = self._runner.run(spec, stdout_path=raw_path)
            context.command_results.append(result)
            parser = RpcClientUserParser()
            context.users = parser.parse(result.stdout)
            logger.debug("Enumerated %d users", len(context.users))
        except CommandTimeoutError:
            context.skip_step("user_enum", "rpcclient user enum timed out")

        # Groups
        spec = rpcclient.build_group_enum_command(target)
        raw_path = self._config.output_base / "raw" / "rpcclient" / "groups.txt"
        try:
            result = self._runner.run(spec, stdout_path=raw_path)
            context.command_results.append(result)
            parser_g = RpcClientGroupParser()
            context.groups = parser_g.parse(result.stdout)
            logger.debug("Enumerated %d groups", len(context.groups))
        except CommandTimeoutError:
            context.skip_step("group_enum", "rpcclient group enum timed out")

        # Domain info
        spec = rpcclient.build_domain_info_command(target)
        raw_path = self._config.output_base / "raw" / "rpcclient" / "domain_info.txt"
        try:
            result = self._runner.run(spec, stdout_path=raw_path)
            context.command_results.append(result)
            domain_parser = RpcClientDomainParser()
            domains = domain_parser.parse(result.stdout)
            if domains:
                context.domain = domains[0]
                logger.debug("Domain: %s", context.domain)
        except CommandTimeoutError:
            context.skip_step("domain_info", "rpcclient domain info timed out")

        # Per-share details via netsharegetinfo
        share_info_parser = RpcClientShareInfoParser()
        for share in context.shares:
            spec = rpcclient.build_share_info_command(target, share.name)
            raw_path = self._config.output_base / "raw" / "rpcclient" / f"shareinfo_{share.name}.txt"
            try:
                result = self._runner.run(spec, stdout_path=raw_path)
                context.command_results.append(result)
                share_details = share_info_parser.parse(result.stdout)
                if share_details:
                    context.share_details[share.name] = share_details[0]
                    # Update share comment from remark if available
                    if share_details[0].get("remark") and not share.comment:
                        share.comment = share_details[0]["remark"]
            except CommandTimeoutError:
                pass

    def _phase_security_validation(self, context: ScanContext) -> None:
        """Phase 8: Run PROTO-001/002/003/004 and validate controls."""
        # Run remaining protocol tests
        for test_id in ("PROTO-001", "PROTO-003", "PROTO-004"):
            if context.get_test_result(test_id) is not None:
                continue  # already run
            test_cls = TEST_REGISTRY.get(test_id)
            if test_cls is None:
                continue
            test = test_cls()
            result = test.run(context)
            context.add_test_result(result)
            logger.debug("Test %s: %s", test_id, result.status)

        # Run permission tests
        for test_id in ("PERM-001", "PERM-002", "PERM-003"):
            test_cls = TEST_REGISTRY.get(test_id)
            if test_cls is None:
                continue
            test = test_cls()
            result = test.run(context)
            context.add_test_result(result)
            logger.debug("Test %s: %s", test_id, result.status)

        # Validate controls
        validator = ControlValidator()
        assessments = validator.assess_all(context)
        for assessment in assessments:
            context.add_control(assessment)

        logger.debug("Controls assessed: %d", len(context.control_assessments))

    def _phase_attack_paths(self, context: ScanContext) -> None:
        """Phase 9: Generate attack paths from validated evidence."""
        evaluator = AttackPathEvaluator()
        paths, blocked = evaluator.evaluate_all(context)
        context.attack_paths.extend(paths)
        context.blocked_paths.extend(blocked)
        logger.debug(
            "Attack paths: %d active, %d blocked",
            len(context.attack_paths),
            len(context.blocked_paths),
        )

    def _phase_reporting(self, context: ScanContext) -> None:
        """Phase 10: Run all registered reporters."""
        for name, reporter_cls in REPORTER_REGISTRY.items():
            try:
                reporter = reporter_cls()
                reporter.write(context)
                logger.debug("Reporter '%s' completed", name)
            except Exception as exc:
                error_msg = f"Reporter '{name}' failed: {exc}"
                context.errors.append(error_msg)
                logger.warning(error_msg)

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def _run_phase(self, name: str, fn, context: ScanContext) -> None:
        """Execute a phase function, catching and recording any exceptions."""
        try:
            fn(context)
        except Exception as exc:
            msg = f"Phase '{name}' failed: {exc}"
            context.errors.append(msg)
            logger.error(msg, exc_info=True)
