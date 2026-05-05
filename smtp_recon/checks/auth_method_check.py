from __future__ import annotations

import dataclasses
import json
import logging

from ..models.auth_method import AuthMethod
from ..models.control import Control
from ..models.finding import Finding
from ..models.result import CheckResult
from ..models.scan_context import ScanContext
from ..parsers.ehlo_parser import EhloParser
from ..tools.manual_smtp_tool import ManualSmtpTool
from .base import BaseCheck

logger = logging.getLogger(__name__)

# Methods considered weak (transmit credentials in cleartext/base64)
_WEAK_METHODS = {"PLAIN", "LOGIN"}
# Methods considered strong
_STRONG_METHODS = {"CRAM-MD5", "DIGEST-MD5", "GSSAPI", "NTLM", "XOAUTH2"}


class AuthMethodCheck(BaseCheck):
    name = "auth_methods"

    def run(self, context: ScanContext) -> CheckResult:
        if not context.open_ports:
            return self._skipped(context.target.ip, "No open ports detected")

        logger.info("[auth_methods] Checking AUTH methods on %s", context.target.ip)

        sessions_dir = context.target_dir / "raw" / "manual_sessions"
        sessions_dir.mkdir(parents=True, exist_ok=True)
        norm_dir = context.target_dir / "normalized"
        norm_dir.mkdir(parents=True, exist_ok=True)

        tool = ManualSmtpTool(host=context.target.ip, timeout=context.timeout)
        parser = EhloParser()
        findings: list[Finding] = []
        controls: list[Control] = []
        evidence_paths: list[str] = []
        errors: list[str] = []
        auth_methods: list[AuthMethod] = []

        for port in context.open_ports:
            try:
                # Pre-TLS EHLO
                log_path = sessions_dir / f"auth_check_plain_{port}.txt"
                _, ehlo_resp = tool.run_ehlo(
                    port=port, ehlo_domain="pentest.local", session_log=log_path
                )
                evidence_paths.append(str(log_path))
                ehlo_result = parser.parse(ehlo_resp)

                for method in ehlo_result.auth_methods:
                    auth_methods.append(
                        AuthMethod(
                            method=method,
                            port=port,
                            advertised_before_tls=True,
                            requires_tls=False,
                        )
                    )

                # Post-TLS EHLO (if STARTTLS available)
                if ehlo_result.starttls:
                    tls_log = sessions_dir / f"auth_check_tls_{port}.txt"
                    tls_result = tool.run_starttls(
                        port=port, ehlo_domain="pentest.local", session_log=tls_log
                    )
                    evidence_paths.append(str(tls_log))
                    if tls_result.get("negotiated") and tls_result.get("ehlo_after"):
                        tls_ehlo = parser.parse(tls_result["ehlo_after"])
                        for method in tls_ehlo.auth_methods:
                            # Update existing or add new
                            existing = next(
                                (a for a in auth_methods if a.method == method and a.port == port),
                                None,
                            )
                            if existing:
                                existing.advertised_after_tls = True
                            else:
                                auth_methods.append(
                                    AuthMethod(
                                        method=method,
                                        port=port,
                                        advertised_after_tls=True,
                                        requires_tls=True,
                                    )
                                )

                # Findings for weak methods
                weak_before_tls = [
                    a for a in auth_methods
                    if a.port == port and a.method in _WEAK_METHODS and a.advertised_before_tls
                ]
                if weak_before_tls:
                    findings.append(
                        Finding(
                            title=f"Weak AUTH methods advertised in plaintext on port {port}",
                            severity="high",
                            category="authentication",
                            description=(
                                f"AUTH {', '.join(a.method for a in weak_before_tls)} "
                                "advertised before STARTTLS. Credentials exposed in plaintext."
                            ),
                            evidence=ehlo_resp[:500],
                            remediation="Only advertise AUTH after STARTTLS negotiation.",
                            port=port,
                        )
                    )

                logger.info(
                    "[auth_methods] Port %d: before-TLS=%s",
                    port,
                    [a.method for a in auth_methods if a.port == port],
                )

            except Exception as exc:
                err_msg = f"Port {port}: {exc}"
                errors.append(err_msg)
                logger.warning("[auth_methods] %s", err_msg)

        # Normalized output
        norm_path = norm_dir / "auth_methods.json"
        norm_path.write_text(
            json.dumps([dataclasses.asdict(a) for a in auth_methods], indent=2),
            encoding="utf-8",
        )

        summary = (
            f"AUTH methods found: "
            f"{list({a.method for a in auth_methods})}"
        )
        status = "success" if auth_methods else "inconclusive"
        logger.info("[auth_methods] Done — %s", summary)

        return CheckResult(
            name=self.name,
            target=context.target.ip,
            port=0,
            status=status,
            summary=summary,
            raw_evidence_paths=evidence_paths,
            normalized_output_paths=[str(norm_path)],
            findings=findings,
            controls_observed=controls,
            errors=errors,
        )
