from __future__ import annotations

import dataclasses
import json
import logging

from ..models.finding import Finding
from ..models.relay_test import RelayTest
from ..models.result import CheckResult
from ..models.scan_context import ScanContext
from ..tools.manual_smtp_tool import ManualSmtpTool
from .base import BaseCheck

logger = logging.getLogger(__name__)


class SpoofingCheck(BaseCheck):
    name = "spoofing"

    def run(self, context: ScanContext) -> CheckResult:
        if context.skip_spoofing:
            return self._skipped(context.target.ip, "Spoofing check skipped (skip_spoofing=True)")
        if not context.open_ports:
            return self._skipped(context.target.ip, "No open ports detected")

        logger.info(
            "[spoofing] Testing spoofing on %s (safe_mode=%s)", context.target.ip, context.safe_mode
        )

        spoof_dir = context.target_dir / "trust_boundary_tests" / "spoofing"
        spoof_dir.mkdir(parents=True, exist_ok=True)
        norm_dir = context.target_dir / "normalized"
        norm_dir.mkdir(parents=True, exist_ok=True)

        domain = context.target.domain or context.target.ip
        tool = ManualSmtpTool(host=context.target.ip, timeout=context.timeout)
        findings: list[Finding] = []
        evidence_paths: list[str] = []
        errors: list[str] = []
        spoof_tests: list[RelayTest] = []

        # Forged addresses to try
        forged_scenarios = [
            (f"admin@{domain}", f"Forged internal admin address: admin@{domain}"),
            (f"root@{domain}", f"Forged internal root address: root@{domain}"),
            ("postmaster@example.com", "Forged postmaster at external domain"),
            ("no-reply@paypal.com", "Forged well-known brand address"),
        ]

        rcpt_to = context.to_address

        for port in context.open_ports:
            for forged_from, scenario_desc in forged_scenarios:
                log_path = spoof_dir / f"spoof_{port}_{forged_from.replace('@', '_at_').replace('.', '_')}.txt"
                try:
                    result = tool.run_spoof_test(
                        port=port,
                        forged_from=forged_from,
                        rcpt_to=rcpt_to,
                        session_log=log_path,
                    )
                    evidence_paths.append(str(log_path))

                    accepted = result.get("accepted", False)
                    spoof_test = RelayTest(
                        port=port,
                        mail_from=forged_from,
                        rcpt_to=rcpt_to,
                        scenario=scenario_desc,
                        mail_from_code=result.get("mail_from_code", 0),
                        rcpt_to_code=result.get("rcpt_to_code", 0),
                        accepted=accepted,
                        safe_mode=context.safe_mode,
                        notes=result.get("error", ""),
                    )
                    spoof_tests.append(spoof_test)

                    logger.info(
                        "[spoofing] Port %d, forged=%s: accepted=%s (mf_code=%d)",
                        port, forged_from, accepted, result.get("mail_from_code", 0),
                    )

                    # MAIL FROM accepted with forged domain address
                    mf_code = result.get("mail_from_code", 0)
                    if mf_code == 250:
                        severity = "high" if "paypal" in forged_from else "medium"
                        findings.append(
                            Finding(
                                title=f"Spoofed MAIL FROM accepted on port {port}",
                                severity=severity,
                                category="spoofing",
                                description=(
                                    f"Server accepted MAIL FROM:<{forged_from}> without authentication. "
                                    f"{scenario_desc}"
                                ),
                                evidence=(
                                    f"MAIL FROM:<{forged_from}> => {mf_code}\n"
                                    f"RCPT TO:<{rcpt_to}> => {result.get('rcpt_to_code', 'N/A')}"
                                ),
                                remediation=(
                                    "Implement SPF, DKIM, and DMARC. "
                                    "Configure the server to reject spoofed sender addresses."
                                ),
                                tags=["spoofing", "email_security"],
                                port=port,
                            )
                        )

                except Exception as exc:
                    err_msg = f"Port {port} spoof ({forged_from}): {exc}"
                    errors.append(err_msg)
                    logger.warning("[spoofing] %s", err_msg)

        # Normalized output
        norm_path = norm_dir / "spoofing_tests.json"
        norm_path.write_text(
            json.dumps([dataclasses.asdict(r) for r in spoof_tests], indent=2),
            encoding="utf-8",
        )

        accepted_count = len([r for r in spoof_tests if r.accepted])
        summary = (
            f"Spoofing: {accepted_count}/{len(spoof_tests)} forged MAIL FROM accepted"
        )
        status = "success" if spoof_tests else ("failed" if errors else "inconclusive")
        logger.info("[spoofing] Done — %s", summary)

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
