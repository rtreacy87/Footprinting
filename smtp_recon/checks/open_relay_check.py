from __future__ import annotations

import dataclasses
import json
import logging

from ..models.finding import Finding
from ..models.relay_test import RelayTest
from ..models.result import CheckResult
from ..models.scan_context import ScanContext
from ..parsers.relay_parser import RelayParser
from ..tools.manual_smtp_tool import ManualSmtpTool
from .base import BaseCheck

logger = logging.getLogger(__name__)

# External domain that is never internal
_EXTERNAL_DOMAIN = "gmail.com"
_EXTERNAL_FROM = "attacker@external-pentest.invalid"
_EXTERNAL_TO = "victim@external-pentest.invalid"


class OpenRelayCheck(BaseCheck):
    name = "open_relay"

    def run(self, context: ScanContext) -> CheckResult:
        if context.skip_relay:
            return self._skipped(context.target.ip, "Open relay check skipped (skip_relay=True)")
        if not context.open_ports:
            return self._skipped(context.target.ip, "No open ports detected")

        logger.info("[open_relay] Testing open relay on %s (safe_mode=%s)", context.target.ip, context.safe_mode)

        relay_dir = context.target_dir / "trust_boundary_tests" / "open_relay"
        relay_dir.mkdir(parents=True, exist_ok=True)
        norm_dir = context.target_dir / "normalized"
        norm_dir.mkdir(parents=True, exist_ok=True)

        tool = ManualSmtpTool(host=context.target.ip, timeout=context.timeout)
        relay_parser = RelayParser()
        findings: list[Finding] = []
        evidence_paths: list[str] = []
        errors: list[str] = []
        relay_tests: list[RelayTest] = []

        domain = context.target.domain or context.target.ip
        internal_from = f"internal@{domain}"
        internal_to = f"internal@{domain}"
        external_from = _EXTERNAL_FROM
        external_to = _EXTERNAL_TO

        test_matrix = [
            ("external->external", external_from, external_to),
            ("internal->external", internal_from, external_to),
            ("external->internal", external_from, internal_to),
            ("internal->internal", internal_from, internal_to),
        ]

        for port in context.open_ports:
            for scenario, mail_from, rcpt_to in test_matrix:
                log_path = relay_dir / f"relay_{port}_{scenario.replace('>', '_')}.txt"
                try:
                    result = tool.run_relay_test(
                        port=port,
                        mail_from=mail_from,
                        rcpt_to=rcpt_to,
                        session_log=log_path,
                    )
                    evidence_paths.append(str(log_path))

                    accepted = result.get("accepted", False)
                    relay_test = RelayTest(
                        port=port,
                        mail_from=mail_from,
                        rcpt_to=rcpt_to,
                        scenario=scenario,
                        mail_from_code=result.get("mail_from_code", 0),
                        rcpt_to_code=result.get("rcpt_to_code", 0),
                        accepted=accepted,
                        safe_mode=context.safe_mode,
                        notes=result.get("error", ""),
                    )
                    relay_tests.append(relay_test)

                    logger.info(
                        "[open_relay] Port %d %s: accepted=%s (rcpt_code=%d)",
                        port, scenario, accepted, result.get("rcpt_to_code", 0),
                    )

                    # Open relay = external->external accepted
                    if scenario == "external->external" and accepted:
                        findings.append(
                            Finding(
                                title=f"OPEN RELAY detected on port {port}",
                                severity="critical",
                                category="open_relay",
                                description=(
                                    f"Port {port} accepted RCPT TO from an external sender "
                                    "to an external recipient — this is a fully open relay."
                                ),
                                evidence=(
                                    f"MAIL FROM:<{mail_from}> => {result.get('mail_from_code')}\n"
                                    f"RCPT TO:<{rcpt_to}> => {result.get('rcpt_to_code')}"
                                ),
                                remediation=(
                                    "Restrict relay to authenticated users or internal networks only. "
                                    "Review mynetworks and relay_domains configuration."
                                ),
                                tags=["open_relay", "critical"],
                                port=port,
                            )
                        )

                    # Internal→external accepted without auth is notable
                    if scenario == "internal->external" and accepted:
                        findings.append(
                            Finding(
                                title=f"Unauthenticated internal→external relay on port {port}",
                                severity="high",
                                category="open_relay",
                                description=(
                                    "Server accepted unauthenticated RCPT TO for an internal sender "
                                    "to an external recipient."
                                ),
                                evidence=(
                                    f"MAIL FROM:<{mail_from}> => {result.get('mail_from_code')}\n"
                                    f"RCPT TO:<{rcpt_to}> => {result.get('rcpt_to_code')}"
                                ),
                                port=port,
                            )
                        )

                except Exception as exc:
                    err_msg = f"Port {port} {scenario}: {exc}"
                    errors.append(err_msg)
                    logger.warning("[open_relay] %s", err_msg)

        # Normalized output
        norm_path = norm_dir / "relay_tests.json"
        norm_path.write_text(
            json.dumps([dataclasses.asdict(r) for r in relay_tests], indent=2),
            encoding="utf-8",
        )

        open_relays = [r for r in relay_tests if r.scenario == "external->external" and r.accepted]
        summary = (
            f"Open relay: {'DETECTED' if open_relays else 'not detected'} "
            f"({len(relay_tests)} scenarios tested)"
        )
        status = "success" if relay_tests else ("failed" if errors else "inconclusive")
        logger.info("[open_relay] Done — %s", summary)

        return CheckResult(
            name=self.name,
            target=context.target.ip,
            port=0,
            status=status,
            summary=summary,
            raw_evidence_paths=evidence_paths,
            normalized_output_paths=[str(norm_path)],
            findings=findings,
            errors=errors,
        )
