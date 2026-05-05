from __future__ import annotations

import dataclasses
import json
import logging

from ..models.finding import Finding
from ..models.result import CheckResult
from ..models.scan_context import ScanContext
from ..models.smtp_user import SmtpUser
from ..parsers.user_enum_parser import UserEnumParser
from ..tools.manual_smtp_tool import ManualSmtpTool
from .base import BaseCheck
from .vrfy_user_enum import CANARY_USERS, DEFAULT_USERS

logger = logging.getLogger(__name__)


class ExpnUserEnumCheck(BaseCheck):
    name = "expn_user_enum"

    def run(self, context: ScanContext) -> CheckResult:
        if context.skip_user_enum:
            return self._skipped(context.target.ip, "User enumeration skipped (skip_user_enum=True)")
        if not context.open_ports:
            return self._skipped(context.target.ip, "No open ports detected")

        logger.info("[expn_user_enum] Starting EXPN enumeration on %s", context.target.ip)

        sessions_dir = context.target_dir / "raw" / "manual_sessions"
        sessions_dir.mkdir(parents=True, exist_ok=True)
        norm_dir = context.target_dir / "identity_enumeration"
        norm_dir.mkdir(parents=True, exist_ok=True)

        if context.wordlist and context.wordlist.exists():
            user_list = context.wordlist.read_text(encoding="utf-8").splitlines()
            user_list = [u.strip() for u in user_list if u.strip()]
        else:
            user_list = list(DEFAULT_USERS)

        all_users = user_list + CANARY_USERS

        tool = ManualSmtpTool(host=context.target.ip, timeout=context.timeout)
        enum_parser = UserEnumParser()
        findings: list[Finding] = []
        evidence_paths: list[str] = []
        errors: list[str] = []
        all_smtp_users: list[SmtpUser] = []

        port = 25 if 25 in context.open_ports else context.open_ports[0]
        log_path = sessions_dir / "expn_session.txt"

        try:
            raw_results = tool.run_expn(port=port, users=all_users, session_log=log_path)
            evidence_paths.append(str(log_path))

            canary_responses = [(u, r) for u, r in raw_results if u in CANARY_USERS]
            canary_fp = enum_parser.detect_canary_false_positive(canary_responses)

            if canary_fp:
                logger.warning("[expn_user_enum] Canary false positive — EXPN unreliable")
                findings.append(
                    Finding(
                        title="EXPN results unreliable (canary false positive)",
                        severity="info",
                        category="user_enumeration",
                        description="Server returned 250 for canary usernames via EXPN.",
                        evidence=str(canary_responses),
                        port=port,
                    )
                )

            first_code = None
            for username, raw_resp in raw_results:
                if username in CANARY_USERS:
                    continue
                user = enum_parser.build_user(
                    username=username,
                    raw_response=raw_resp,
                    method="EXPN",
                    port=port,
                    canary_confirmed=canary_fp,
                )
                all_smtp_users.append(user)
                if first_code is None:
                    first_code = user.response_code

            # EXPN blocked is 502
            if first_code in (502, 500):
                findings.append(
                    Finding(
                        title="EXPN command blocked",
                        severity="info",
                        category="security_control",
                        description="Server has disabled the EXPN command.",
                        evidence=f"Response code: {first_code}",
                        port=port,
                    )
                )

            confirmed = [u for u in all_smtp_users if u.status == "confirmed"]
            if confirmed and not canary_fp:
                findings.append(
                    Finding(
                        title=f"Mailing lists/users enumerated via EXPN on port {port}",
                        severity="medium",
                        category="user_enumeration",
                        description=f"EXPN revealed {len(confirmed)} valid mailbox(es)/list(s).",
                        evidence=", ".join(u.username for u in confirmed),
                        remediation="Disable the EXPN command.",
                        tags=["user_enum", "expn"],
                        port=port,
                    )
                )

        except Exception as exc:
            err_msg = f"EXPN session error: {exc}"
            errors.append(err_msg)
            logger.warning("[expn_user_enum] %s", err_msg)

        norm_path = norm_dir / "expn_users.json"
        norm_path.write_text(
            json.dumps([dataclasses.asdict(u) for u in all_smtp_users], indent=2),
            encoding="utf-8",
        )

        confirmed_count = len([u for u in all_smtp_users if u.status == "confirmed"])
        summary = (
            f"EXPN: {confirmed_count} confirmed out of {len(all_smtp_users)} tested on port {port}"
        )
        status = "success" if all_smtp_users else ("failed" if errors else "blocked")
        logger.info("[expn_user_enum] Done — %s", summary)

        return CheckResult(
            name=self.name,
            target=context.target.ip,
            port=port,
            status=status,
            summary=summary,
            raw_evidence_paths=evidence_paths,
            normalized_output_paths=[str(norm_path)],
            findings=findings,
            errors=errors,
        )
