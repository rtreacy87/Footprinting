from __future__ import annotations

"""
manual_smtp_tool.py

Thin wrapper around SmtpSocketExecutor that saves session transcripts.
Used by checks that need direct socket-level SMTP interaction.
"""

from pathlib import Path

from ..executors.smtp_socket_executor import SmtpSocketExecutor


class ManualSmtpTool:
    """High-level façade over SmtpSocketExecutor for use in checks."""

    def __init__(self, host: str, timeout: int = 30) -> None:
        self._executor = SmtpSocketExecutor(host=host, timeout=timeout)

    def get_banner(self, port: int, session_log: Path | None = None) -> str:
        return self._executor.get_banner(port, session_log)

    def run_ehlo(
        self,
        port: int,
        ehlo_domain: str = "test.local",
        session_log: Path | None = None,
    ) -> tuple[str, str]:
        return self._executor.run_ehlo(port, ehlo_domain, session_log)

    def run_starttls(
        self,
        port: int,
        ehlo_domain: str = "test.local",
        session_log: Path | None = None,
    ) -> dict:
        return self._executor.run_starttls(port, ehlo_domain, session_log)

    def run_vrfy(
        self,
        port: int,
        users: list[str],
        session_log: Path | None = None,
    ) -> list[tuple[str, str]]:
        return self._executor.run_vrfy(port, users, session_log)

    def run_expn(
        self,
        port: int,
        users: list[str],
        session_log: Path | None = None,
    ) -> list[tuple[str, str]]:
        return self._executor.run_expn(port, users, session_log)

    def run_rcpt_to(
        self,
        port: int,
        users: list[str],
        domain: str,
        mail_from: str = "test@test.local",
        session_log: Path | None = None,
    ) -> list[tuple[str, str]]:
        return self._executor.run_rcpt_to(port, users, domain, mail_from, session_log)

    def run_relay_test(
        self,
        port: int,
        mail_from: str,
        rcpt_to: str,
        session_log: Path | None = None,
    ) -> dict:
        return self._executor.run_relay_test(port, mail_from, rcpt_to, session_log)

    def run_spoof_test(
        self,
        port: int,
        forged_from: str,
        rcpt_to: str,
        session_log: Path | None = None,
    ) -> dict:
        return self._executor.run_spoof_test(port, forged_from, rcpt_to, session_log)
