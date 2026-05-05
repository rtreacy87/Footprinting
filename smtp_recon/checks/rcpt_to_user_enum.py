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


class RcptToUserEnumCheck(BaseCheck):
    name = "rcpt_to_user_enum"

    def run(self, context: ScanContext) -> CheckResult:
        if context.skip_user_enum:
            return self._skipped(context.target.ip, "User enumeration skipped (skip_user_enum=True)")
        if not context.open_ports:
            return self._skipped(context.target.ip, "No open ports detected")

        # Need a domain for RCPT TO. Prefer configured domain, then server
        # hostname from the EHLO session (e.g. "mail1"), then "localhost".
        # Never use the raw target IP — servers reject that with 501.
        domain = context.target.domain or self._server_hostname(context, port) or "localhost"

        logger.info(
            "[rcpt_to_user_enum] Starting RCPT TO enumeration on %s (domain=%s)",
            context.target.ip,
            domain,
        )

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
        log_path = sessions_dir / "rcpt_to_session.txt"

        try:
            raw_results = tool.run_rcpt_to(
                port=port,
                users=all_users,
                domain=domain,
                mail_from=context.from_address,
                session_log=log_path,
            )
            evidence_paths.append(str(log_path))

            canary_responses = [(u, r) for u, r in raw_results if u in CANARY_USERS]
            canary_fp = enum_parser.detect_canary_false_positive(canary_responses)

            if canary_fp:
                logger.warning("[rcpt_to_user_enum] Canary false positive — RCPT TO unreliable")
                findings.append(
                    Finding(
                        title="RCPT TO results unreliable (canary false positive)",
                        severity="info",
                        category="user_enumeration",
                        description=(
                            "Server accepted RCPT TO for canary usernames. "
                            "This may indicate an open relay or catch-all configuration."
                        ),
                        evidence=str(canary_responses),
                        port=port,
                    )
                )

            for username, raw_resp in raw_results:
                if username in CANARY_USERS:
                    continue
                # Handle error strings from socket failures
                if raw_resp.startswith("ERROR:"):
                    errors.append(f"{username}: {raw_resp}")
                    continue
                user = enum_parser.build_user(
                    username=username,
                    raw_response=raw_resp,
                    method="RCPT_TO",
                    port=port,
                    canary_confirmed=canary_fp,
                )
                all_smtp_users.append(user)

            confirmed = [u for u in all_smtp_users if u.status == "confirmed"]
            if confirmed and not canary_fp:
                findings.append(
                    Finding(
                        title=f"Valid users enumerated via RCPT TO on port {port}",
                        severity="high",
                        category="user_enumeration",
                        description=(
                            f"Server accepted RCPT TO for {len(confirmed)} address(es). "
                            "These are valid mailboxes."
                        ),
                        evidence=", ".join(f"{u.username}@{domain}" for u in confirmed),
                        remediation=(
                            "Configure the server to return identical responses regardless "
                            "of whether the recipient exists."
                        ),
                        tags=["user_enum", "rcpt_to"],
                        port=port,
                    )
                )

        except Exception as exc:
            err_msg = f"RCPT TO session error: {exc}"
            errors.append(err_msg)
            logger.warning("[rcpt_to_user_enum] %s", err_msg)

        norm_path = norm_dir / "rcpt_to_users.json"
        norm_path.write_text(
            json.dumps([dataclasses.asdict(u) for u in all_smtp_users], indent=2),
            encoding="utf-8",
        )

        confirmed_count = len([u for u in all_smtp_users if u.status == "confirmed"])
        summary = (
            f"RCPT TO: {confirmed_count} confirmed out of {len(all_smtp_users)} tested "
            f"on port {port} (domain={domain})"
        )
        status = "success" if all_smtp_users else ("failed" if errors else "inconclusive")
        logger.info("[rcpt_to_user_enum] Done — %s", summary)

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

    @staticmethod
    def _server_hostname(context: ScanContext, port: int) -> str:
        """Extract server hostname from the previously-captured EHLO session file.

        After EHLO, the server's first 250-* line is always the server hostname,
        e.g. "S: 250-mail1". Subsequent lines are capability keywords (all-caps).
        """
        sessions_dir = context.target_dir / "raw" / "manual_sessions"
        candidates = [
            sessions_dir / f"ehlo_session_{port}.txt",
            sessions_dir / "ehlo_session.txt",
            sessions_dir / f"starttls_session_{port}.txt",
        ]
        for path in candidates:
            if not path.exists():
                continue
            found_ehlo = False
            for line in path.read_text(encoding="utf-8").splitlines():
                if line.startswith(("C: EHLO", "C: HELO")):
                    found_ehlo = True
                    continue
                if found_ehlo and line.startswith("S: 250") and len(line) > 7:
                    # "S: 250-" or "S: 250 " — 7 chars before the content
                    hostname = line[7:].strip().split()[0]
                    if hostname:
                        return hostname
                    break
        return ""
