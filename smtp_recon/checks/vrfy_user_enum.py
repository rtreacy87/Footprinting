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
from ..tools.smtp_user_enum_tool import SmtpUserEnumTool
from .base import BaseCheck

logger = logging.getLogger(__name__)

DEFAULT_USERS = [
    "admin", "root", "postmaster", "user", "test", "info", "mail",
    "support", "operator", "www", "ftp", "sales", "service",
    "webmaster", "abuse", "noc", "security", "hostmaster", "mailer-daemon",
]

CANARY_USERS = ["notarealuser-canary", "zzz-smtp-recon-canary"]


class VrfyUserEnumCheck(BaseCheck):
    name = "vrfy_user_enum"

    def run(self, context: ScanContext) -> CheckResult:
        if context.skip_user_enum:
            return self._skipped(context.target.ip, "User enumeration skipped (skip_user_enum=True)")
        if not context.open_ports:
            return self._skipped(context.target.ip, "No open ports detected")

        logger.info("[vrfy_user_enum] Starting VRFY enumeration on %s", context.target.ip)

        sessions_dir = context.target_dir / "raw" / "manual_sessions"
        sessions_dir.mkdir(parents=True, exist_ok=True)
        norm_dir = context.target_dir / "identity_enumeration"
        norm_dir.mkdir(parents=True, exist_ok=True)

        port = 25 if 25 in context.open_ports else context.open_ports[0]
        findings: list[Finding] = []
        evidence_paths: list[str] = []
        errors: list[str] = []
        all_smtp_users: list[SmtpUser] = []

        # --- Primary path: smtp-user-enum tool (system binary or local Perl script) ---
        if context.wordlist and context.wordlist.exists() and SmtpUserEnumTool.is_available():
            all_smtp_users, findings, evidence_paths, errors = self._run_with_tool(
                context, port, sessions_dir, norm_dir
            )
        else:
            # --- Fallback: raw socket VRFY with per-user reconnect ---
            if not SmtpUserEnumTool.is_available():
                logger.info("[vrfy_user_enum] smtp-user-enum not found — using socket VRFY fallback")
            all_smtp_users, findings, evidence_paths, errors = self._run_socket_vrfy(
                context, port, sessions_dir, norm_dir
            )

        norm_path = norm_dir / "vrfy_users.json"
        norm_path.write_text(
            json.dumps([dataclasses.asdict(u) for u in all_smtp_users], indent=2),
            encoding="utf-8",
        )

        confirmed_count = sum(1 for u in all_smtp_users if u.status == "confirmed")
        summary = f"VRFY: {confirmed_count} confirmed users out of {len(all_smtp_users)} tested on port {port}"
        status = "success" if all_smtp_users else ("failed" if errors else "blocked")
        logger.info("[vrfy_user_enum] Done — %s", summary)

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

    # ------------------------------------------------------------------
    # Primary: smtp-user-enum tool
    # ------------------------------------------------------------------

    def _run_with_tool(
        self,
        context: ScanContext,
        port: int,
        sessions_dir,
        norm_dir,
    ):
        tool = SmtpUserEnumTool()
        # Build combined wordlist: user candidates + canaries
        user_list = context.wordlist.read_text(encoding="utf-8").splitlines()
        user_list = [u.strip() for u in user_list if u.strip()]
        combined = user_list + CANARY_USERS

        import tempfile
        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".txt", delete=False, encoding="utf-8"
        ) as tmp:
            tmp.write("\n".join(combined) + "\n")
            tmp_path = tmp.name

        raw_out_path = sessions_dir / "smtp_user_enum_vrfy.txt"
        result = tool.enumerate(
            target=context.target.ip,
            port=port,
            userlist_path=__import__("pathlib").Path(tmp_path),
            mode="VRFY",
            workers=60,
            query_timeout=max(context.timeout, 20),
            timeout=max(len(combined) * 5, 300),
            output_path=raw_out_path,
        )
        __import__("os").unlink(tmp_path)

        evidence_paths = [str(raw_out_path)]
        findings: list[Finding] = []
        errors: list[str] = []
        all_smtp_users: list[SmtpUser] = []

        if result.return_code == -2:
            # Tool vanished between is_available() check and execution
            logger.warning("[vrfy_user_enum] smtp-user-enum disappeared — falling back to socket")
            return self._run_socket_vrfy(context, port, sessions_dir, norm_dir)

        if result.stderr:
            logger.debug("[vrfy_user_enum] smtp-user-enum stderr: %s", result.stderr[:200])

        # Check canary results to detect catch-all false positives
        canary_hits = [c for c in CANARY_USERS if c in (result.stdout or "")]
        canary_fp = any(
            f"{context.target.ip}: {c} exists" in (result.stdout or "")
            for c in CANARY_USERS
        )

        if canary_fp:
            logger.warning("[vrfy_user_enum] Canary false positive — smtp-user-enum unreliable")
            findings.append(Finding(
                title="VRFY results unreliable (canary false positive)",
                severity="info",
                category="user_enumeration",
                description="Server confirmed canary usernames via VRFY — results are not reliable.",
                evidence=str(canary_hits),
                port=port,
            ))

        # Parse confirmed hits
        hits = SmtpUserEnumTool.parse_hits(result.stdout or "", context.target.ip)
        real_hits = [h for h in hits if h not in CANARY_USERS]

        for username in user_list:
            is_hit = username in real_hits and not canary_fp
            all_smtp_users.append(SmtpUser(
                username=username,
                method="VRFY",
                response_code=250 if is_hit else 550,
                response_text="exists" if is_hit else "not found",
                status="confirmed" if is_hit else "rejected",
                port=port,
                is_canary=False,
            ))

        confirmed = [u for u in all_smtp_users if u.status == "confirmed"]
        if confirmed and not canary_fp:
            findings.append(Finding(
                title=f"Valid users enumerated via VRFY on port {port}",
                severity="medium",
                category="user_enumeration",
                description=f"smtp-user-enum confirmed {len(confirmed)} user(s) via VRFY.",
                evidence=", ".join(u.username for u in confirmed),
                remediation="Disable or restrict the VRFY command.",
                tags=["user_enum", "vrfy"],
                port=port,
            ))

        return all_smtp_users, findings, evidence_paths, errors

    # ------------------------------------------------------------------
    # Fallback: raw socket VRFY with per-user reconnect
    # ------------------------------------------------------------------

    def _run_socket_vrfy(self, context: ScanContext, port: int, sessions_dir, norm_dir):
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

        log_path = sessions_dir / "vrfy_session.txt"
        try:
            raw_results = tool.run_vrfy(port=port, users=all_users, session_log=log_path)
            evidence_paths.append(str(log_path))

            canary_responses = [(u, r) for u, r in raw_results if u in CANARY_USERS]
            canary_fp = enum_parser.detect_canary_false_positive(canary_responses)

            canary_codes = {int(r[:3]) for _, r in canary_responses if r[:3].isdigit()}
            canary_explicit_reject = bool(canary_codes) and canary_codes.issubset(
                {550, 551, 553, 500, 502}
            )

            if canary_fp:
                findings.append(Finding(
                    title="VRFY results unreliable (canary false positive)",
                    severity="info",
                    category="user_enumeration",
                    description="Server returned 250 for canary usernames.",
                    evidence=str(canary_responses),
                    port=port,
                ))

            first_code = None
            for username, raw_resp in raw_results:
                if username in CANARY_USERS:
                    continue
                user = enum_parser.build_user(
                    username=username, raw_response=raw_resp,
                    method="VRFY", port=port, canary_confirmed=canary_fp,
                )
                # Upgrade 252 to confirmed when canary baseline is explicit rejection
                if user.status == "ambiguous" and canary_explicit_reject:
                    user = SmtpUser(
                        username=user.username, method=user.method,
                        response_code=user.response_code, response_text=user.response_text,
                        status="confirmed", port=user.port, is_canary=user.is_canary,
                    )
                all_smtp_users.append(user)
                if first_code is None:
                    first_code = user.response_code

            if first_code in (502, 500):
                findings.append(Finding(
                    title="VRFY command blocked",
                    severity="info",
                    category="security_control",
                    description="Server has disabled the VRFY command.",
                    evidence=f"Response code: {first_code}",
                    port=port,
                ))

            confirmed = [u for u in all_smtp_users if u.status == "confirmed"]
            if confirmed and not canary_fp:
                findings.append(Finding(
                    title=f"Valid users enumerated via VRFY on port {port}",
                    severity="medium",
                    category="user_enumeration",
                    description=f"Confirmed {len(confirmed)} user(s) via VRFY.",
                    evidence=", ".join(u.username for u in confirmed),
                    remediation="Disable or restrict the VRFY command.",
                    tags=["user_enum", "vrfy"],
                    port=port,
                ))

        except Exception as exc:
            err_msg = f"VRFY session error: {exc}"
            errors.append(err_msg)
            logger.warning("[vrfy_user_enum] %s", err_msg)

        return all_smtp_users, findings, evidence_paths, errors
