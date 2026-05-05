from __future__ import annotations


class SmtpReconError(Exception):
    """Base exception for smtp_recon package."""


class SmtpConnectionError(SmtpReconError):
    """Raised when a socket/SMTP connection fails."""

    def __init__(self, host: str, port: int, reason: str = "") -> None:
        self.host = host
        self.port = port
        self.reason = reason
        msg = f"Cannot connect to {host}:{port}"
        if reason:
            msg += f" — {reason}"
        super().__init__(msg)


class SmtpTimeoutError(SmtpReconError):
    """Raised when an SMTP operation times out."""

    def __init__(self, host: str, port: int, timeout: int) -> None:
        super().__init__(f"Timeout ({timeout}s) connecting to {host}:{port}")


class SmtpCommandError(SmtpReconError):
    """Raised when an unexpected SMTP response is received."""

    def __init__(self, command: str, code: int, text: str) -> None:
        super().__init__(f"SMTP command {command!r} returned {code}: {text}")


class ToolNotFoundError(SmtpReconError):
    """Raised when a required external tool is not present on PATH."""

    def __init__(self, tool: str) -> None:
        super().__init__(f"Required tool not found on PATH: {tool}")
