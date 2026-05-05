from __future__ import annotations

import json
import logging
from datetime import datetime, timezone
from pathlib import Path

from ..agent.do_not_retry_builder import DoNotRetryBuilder
from ..agent.next_action_builder import NextActionBuilder
from ..analyzers.attack_path_analyzer import AttackPathAnalyzer
from ..analyzers.capability_analyzer import CapabilityAnalyzer
from ..analyzers.control_analyzer import ControlAnalyzer
from ..analyzers.identity_analyzer import IdentityAnalyzer
from ..analyzers.relay_analyzer import RelayAnalyzer
from ..checks.registry import CHECK_REGISTRY
from ..config import SmtpReconConfig
from ..models.finding import Finding
from ..models.result import CheckResult
from ..models.scan_context import ScanContext
from ..models.target import Target
from ..report.executive_summary import build_executive_summary
from ..report.remediation import build_remediation_plan
from ..report.technical_summary import build_technical_summary
from ..writers.json_writer import JsonWriter
from ..writers.markdown_writer import MarkdownWriter
from ..writers.output_tree import create_output_tree

logger = logging.getLogger(__name__)

# Checks that require skip_user_enum flag
_USER_ENUM_CHECKS = {"vrfy_user_enum", "expn_user_enum", "rcpt_to_user_enum"}
# Checks that require skip_relay flag
_RELAY_CHECKS = {"open_relay"}
# Checks that require skip_spoofing flag
_SPOOFING_CHECKS = {"spoofing"}


class SmtpOrchestrator:
    def __init__(self, config: SmtpReconConfig) -> None:
        self._config = config
        self._setup_logging()

    def _setup_logging(self) -> None:
        level = logging.DEBUG if self._config.verbose else logging.INFO
        logging.basicConfig(
            format="%(asctime)s [%(levelname)s] %(name)s — %(message)s",
            level=level,
        )

    def run(self) -> list[CheckResult]:
        config = self._config

        # 1. Build ScanContext from config
        target = Target(
            ip=config.target,
            domain=config.domain,
            ports=config.ports,
        )
        wordlist = Path(config.wordlist) if config.wordlist else None
        output_root = Path(config.output_root)

        context = ScanContext(
            target=target,
            output_root=output_root,
            wordlist=wordlist,
            from_address=config.from_address,
            to_address=config.to_address,
            safe_mode=config.safe_mode,
            timeout=config.timeout,
            verbose=config.verbose,
            skip_relay=config.skip_relay,
            skip_spoofing=config.skip_spoofing,
            skip_user_enum=config.skip_user_enum,
        )

        # 2. Create output tree
        create_output_tree(context)

        # Write metadata
        meta_path = context.target_dir / "metadata" / "scan_config.json"
        meta_path.write_text(
            json.dumps(
                {
                    "target": config.target,
                    "domain": config.domain,
                    "ports": config.ports,
                    "safe_mode": config.safe_mode,
                    "skip_relay": config.skip_relay,
                    "skip_spoofing": config.skip_spoofing,
                    "skip_user_enum": config.skip_user_enum,
                    "timeout": config.timeout,
                    "started_at": datetime.now(timezone.utc).isoformat(),
                },
                indent=2,
            ),
            encoding="utf-8",
        )

        logger.info("=== SmtpOrchestrator starting scan of %s ===", config.target)

        # 3. Run checks from CHECK_REGISTRY in order
        results: list[CheckResult] = []

        for check_name, check_class in CHECK_REGISTRY.items():
            # Skip based on context flags
            if check_name in _USER_ENUM_CHECKS and config.skip_user_enum:
                logger.info("[orchestrator] Skipping %s (skip_user_enum)", check_name)
                results.append(
                    CheckResult(
                        name=check_name,
                        target=config.target,
                        port=0,
                        status="skipped",
                        summary="Skipped by configuration (skip_user_enum=True)",
                    )
                )
                continue

            if check_name in _RELAY_CHECKS and config.skip_relay:
                logger.info("[orchestrator] Skipping %s (skip_relay)", check_name)
                results.append(
                    CheckResult(
                        name=check_name,
                        target=config.target,
                        port=0,
                        status="skipped",
                        summary="Skipped by configuration (skip_relay=True)",
                    )
                )
                continue

            if check_name in _SPOOFING_CHECKS and config.skip_spoofing:
                logger.info("[orchestrator] Skipping %s (skip_spoofing)", check_name)
                results.append(
                    CheckResult(
                        name=check_name,
                        target=config.target,
                        port=0,
                        status="skipped",
                        summary="Skipped by configuration (skip_spoofing=True)",
                    )
                )
                continue

            # Early abort if port_detection found nothing
            if check_name != "port_detection" and not context.open_ports:
                # port_detection already ran and found nothing
                port_det = next(
                    (r for r in results if r.name == "port_detection"), None
                )
                if port_det and port_det.status == "failed":
                    logger.info(
                        "[orchestrator] Skipping %s — no open ports", check_name
                    )
                    results.append(
                        CheckResult(
                            name=check_name,
                            target=config.target,
                            port=0,
                            status="skipped",
                            summary="Skipped — no SMTP ports detected",
                        )
                    )
                    continue

            logger.info("[orchestrator] Running check: %s", check_name)
            check = check_class()
            try:
                result = check.run(context)
            except Exception as exc:
                logger.exception("[orchestrator] Check %s raised an unhandled exception", check_name)
                result = CheckResult(
                    name=check_name,
                    target=config.target,
                    port=0,
                    status="failed",
                    summary=f"Unhandled exception: {exc}",
                    errors=[str(exc)],
                )
            results.append(result)
            logger.info(
                "[orchestrator] Check %s → status=%s", check_name, result.status
            )

        # 4. Collect all findings from check results
        all_findings: list[Finding] = []
        for result in results:
            for finding in result.findings:
                if isinstance(finding, Finding):
                    all_findings.append(finding)

        # 5. Run analyzers
        logger.info("[orchestrator] Running analyzers")
        cap_findings = CapabilityAnalyzer().analyze(context, results)
        id_findings = IdentityAnalyzer().analyze(context, results)
        relay_findings = RelayAnalyzer().analyze(context, results)
        controls = ControlAnalyzer().analyze(context, results)
        all_findings.extend(cap_findings + id_findings + relay_findings)

        # 6. Write normalized outputs (per-check already done; write aggregate)
        logger.info("[orchestrator] Writing outputs")
        json_writer = JsonWriter()
        json_writer.write_results(
            context,
            results,
            extra={"all_findings": all_findings, "controls": controls},
        )

        # 7. Build agent inputs
        attack_paths = AttackPathAnalyzer().analyze(context, results, all_findings)
        NextActionBuilder().build(context, results, attack_paths)
        DoNotRetryBuilder().build(context, results)

        # 8. Build reports
        build_executive_summary(context, results, all_findings)
        build_technical_summary(context, results, all_findings)
        build_remediation_plan(context, all_findings)

        md_writer = MarkdownWriter()
        md_writer.write(context, results, all_findings, attack_paths)

        # Update metadata with completion time
        meta_path.write_text(
            json.dumps(
                {
                    "target": config.target,
                    "domain": config.domain,
                    "ports": config.ports,
                    "safe_mode": config.safe_mode,
                    "open_ports_found": context.open_ports,
                    "skip_relay": config.skip_relay,
                    "skip_spoofing": config.skip_spoofing,
                    "skip_user_enum": config.skip_user_enum,
                    "timeout": config.timeout,
                    "completed_at": datetime.now(timezone.utc).isoformat(),
                    "total_findings": len(all_findings),
                },
                indent=2,
            ),
            encoding="utf-8",
        )

        logger.info(
            "=== SmtpOrchestrator complete — %d checks, %d findings, output at %s ===",
            len(results),
            len(all_findings),
            context.target_dir,
        )

        # 9. Return results
        return results
