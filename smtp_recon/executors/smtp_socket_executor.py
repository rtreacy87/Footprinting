from __future__ import annotations

import logging
import socket
import ssl
import time
from pathlib import Path
from typing import Iterator

logger = logging.getLogger(__name__)

_CRLF = b"\r\n"


class SmtpSocketSession:
    """
    Low-level SMTP socket session.

    Wraps a plain or TLS-upgraded socket and exposes send/recv helpers.
    Intended to be used as a context manager.
    """

    def __init__(
        self,
        host: str,
        port: int,
        timeout: int = 30,
        session_log_path: Path | None = None,
    ) -> None:
        self._host = host
        self._port = port
        self._timeout = timeout
        self._log_path = session_log_path
        self._sock: socket.socket | ssl.SSLSocket | None = None
        self._log_lines: list[str] = []
        self._tls_active = False

    # ------------------------------------------------------------------
    # Context manager
    # ------------------------------------------------------------------
    def __enter__(self) -> "SmtpSocketSession":
        self._connect()
        return self

    def __exit__(self, *_: object) -> None:
        self.close()

    # ------------------------------------------------------------------
    # Connection management
    # ------------------------------------------------------------------
    def _connect(self) -> None:
        raw = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        raw.settimeout(self._timeout)
        raw.connect((self._host, self._port))
        self._sock = raw
        logger.debug("Connected to %s:%d", self._host, self._port)

    def close(self) -> None:
        if self._sock:
            try:
                self._send_raw(b"QUIT\r\n")
            except Exception:
                pass
            try:
                self._sock.close()
            except Exception:
                pass
            self._sock = None
        self._flush_log()

    # ------------------------------------------------------------------
    # Low-level I/O
    # ------------------------------------------------------------------
    def _send_raw(self, data: bytes) -> None:
        if self._sock is None:
            raise RuntimeError("Socket is not connected")
        self._sock.sendall(data)

    def _recv_line(self) -> bytes:
        """Read bytes until CRLF."""
        if self._sock is None:
            raise RuntimeError("Socket is not connected")
        buf = b""
        while True:
            chunk = self._sock.recv(1)
            if not chunk:
                break
            buf += chunk
            if buf.endswith(b"\n"):
                break
        return buf

    def _recv_response(self) -> str:
        """
        Read a full multi-line SMTP response (handles 250- continuation lines).
        Returns the raw response as a string.
        """
        lines = []
        while True:
            line = self._recv_line()
            decoded = line.decode("utf-8", errors="replace").rstrip("\r\n")
            lines.append(decoded)
            self._log_lines.append(f"S: {decoded}")
            # A line starting with "NNN " (space) is the last line of the response
            if len(decoded) >= 4 and decoded[3] == " ":
                break
            # A line starting with "NNN-" continues
            if len(decoded) < 4:
                break
        return "\n".join(lines)

    # ------------------------------------------------------------------
    # Public helpers
    # ------------------------------------------------------------------
    def read_banner(self) -> str:
        """Read the initial 220 banner."""
        return self._recv_response()

    def send_command(self, command: str) -> str:
        """Send a command and return the full response."""
        self._log_lines.append(f"C: {command}")
        logger.debug(">> %s", command)
        self._send_raw(command.encode("utf-8") + _CRLF)
        response = self._recv_response()
        logger.debug("<< %s", response.splitlines()[0] if response else "")
        return response

    def upgrade_to_tls(self) -> None:
        """
        Upgrade the current plain socket to TLS after STARTTLS negotiation.
        The caller must have already sent STARTTLS and received 220.
        """
        if self._sock is None:
            raise RuntimeError("Socket is not connected")
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        self._sock = ctx.wrap_socket(self._sock, server_hostname=self._host)
        self._tls_active = True
        logger.debug("TLS negotiation complete")

    @property
    def tls_active(self) -> bool:
        return self._tls_active

    def get_peer_cert(self) -> dict | None:
        if isinstance(self._sock, ssl.SSLSocket):
            return self._sock.getpeercert()
        return None

    def get_cipher(self) -> tuple | None:
        if isinstance(self._sock, ssl.SSLSocket):
            return self._sock.cipher()
        return None

    # ------------------------------------------------------------------
    # Session log
    # ------------------------------------------------------------------
    def _flush_log(self) -> None:
        if self._log_path and self._log_lines:
            self._log_path.parent.mkdir(parents=True, exist_ok=True)
            self._log_path.write_text("\n".join(self._log_lines) + "\n", encoding="utf-8")


class SmtpSocketExecutor:
    """
    Higher-level SMTP executor that manages sessions and provides
    convenience methods for common SMTP interactions.
    """

    def __init__(self, host: str, timeout: int = 30) -> None:
        self._host = host
        self._timeout = timeout

    def get_banner(self, port: int, session_log: Path | None = None) -> str:
        """Open a connection and return only the 220 banner."""
        with SmtpSocketSession(
            self._host, port, self._timeout, session_log
        ) as session:
            return session.read_banner()

    def run_ehlo(
        self, port: int, ehlo_domain: str = "test.local", session_log: Path | None = None
    ) -> tuple[str, str]:
        """
        Return (banner, ehlo_response).
        Falls back to HELO if EHLO returns 500/502.
        """
        with SmtpSocketSession(
            self._host, port, self._timeout, session_log
        ) as session:
            banner = session.read_banner()
            ehlo_resp = session.send_command(f"EHLO {ehlo_domain}")
            if ehlo_resp.startswith(("500", "502")):
                ehlo_resp = session.send_command(f"HELO {ehlo_domain}")
            return banner, ehlo_resp

    def run_starttls(
        self, port: int, ehlo_domain: str = "test.local", session_log: Path | None = None
    ) -> dict:
        """
        Attempt STARTTLS.  Returns a result dict with keys:
        advertised, negotiated, tls_version, cipher, cert_cn, error.
        """
        result: dict = {
            "advertised": False,
            "negotiated": False,
            "tls_version": "",
            "cipher": "",
            "cert_cn": "",
            "error": "",
            "ehlo_before": "",
            "ehlo_after": "",
        }
        try:
            with SmtpSocketSession(
                self._host, port, self._timeout, session_log
            ) as session:
                session.read_banner()
                ehlo_resp = session.send_command(f"EHLO {ehlo_domain}")
                result["ehlo_before"] = ehlo_resp

                if "STARTTLS" in ehlo_resp.upper():
                    result["advertised"] = True
                    starttls_resp = session.send_command("STARTTLS")
                    if starttls_resp.startswith("220"):
                        session.upgrade_to_tls()
                        result["negotiated"] = True
                        cipher_info = session.get_cipher()
                        if cipher_info:
                            result["tls_version"] = cipher_info[1] or ""
                            result["cipher"] = cipher_info[0] or ""
                        cert = session.get_peer_cert()
                        if cert:
                            subject = dict(x[0] for x in cert.get("subject", []))
                            result["cert_cn"] = subject.get("commonName", "")
                        # Re-EHLO after TLS
                        ehlo_after = session.send_command(f"EHLO {ehlo_domain}")
                        result["ehlo_after"] = ehlo_after
                    else:
                        result["error"] = f"STARTTLS rejected: {starttls_resp}"
        except Exception as exc:
            result["error"] = str(exc)
        return result

    def run_vrfy(
        self,
        port: int,
        users: list[str],
        session_log: Path | None = None,
    ) -> list[tuple[str, str]]:
        """
        Run VRFY for each user with a fresh connection per user.

        Reconnecting per user avoids server-side "too many errors" limits
        (e.g. 421 after ~20 consecutive failed VRFYs).
        """
        results = []
        log_lines: list[str] = [f"# VRFY enumeration against {self._host}:{port}"]

        for user in users:
            try:
                with SmtpSocketSession(self._host, port, self._timeout) as session:
                    session.read_banner()
                    session.send_command("EHLO test.local")
                    resp = session.send_command(f"VRFY {user}")
                    results.append((user, resp))
                    log_lines.append(f"C: VRFY {user}")
                    log_lines.append(f"S: {resp.splitlines()[0]}")
            except Exception as exc:
                logger.warning("VRFY error for %s: %s", user, exc)
                results.append((user, f"ERROR: {exc}"))

        if session_log:
            session_log.parent.mkdir(parents=True, exist_ok=True)
            session_log.write_text("\n".join(log_lines) + "\n", encoding="utf-8")

        return results

    def run_expn(
        self,
        port: int,
        users: list[str],
        session_log: Path | None = None,
    ) -> list[tuple[str, str]]:
        """
        Run EXPN for each user with a fresh connection per user.
        """
        results = []
        log_lines: list[str] = [f"# EXPN enumeration against {self._host}:{port}"]

        for user in users:
            try:
                with SmtpSocketSession(self._host, port, self._timeout) as session:
                    session.read_banner()
                    session.send_command("EHLO test.local")
                    resp = session.send_command(f"EXPN {user}")
                    results.append((user, resp))
                    log_lines.append(f"C: EXPN {user}")
                    log_lines.append(f"S: {resp.splitlines()[0]}")
            except Exception as exc:
                logger.warning("EXPN error for %s: %s", user, exc)
                results.append((user, f"ERROR: {exc}"))

        if session_log:
            session_log.parent.mkdir(parents=True, exist_ok=True)
            session_log.write_text("\n".join(log_lines) + "\n", encoding="utf-8")

        return results

    def run_rcpt_to(
        self,
        port: int,
        users: list[str],
        domain: str,
        mail_from: str = "test@test.local",
        session_log: Path | None = None,
    ) -> list[tuple[str, str]]:
        """
        Run MAIL FROM + RCPT TO enumeration.  Opens one session per user to
        avoid state leakage.  Returns list of (username, rcpt_response).
        """
        results = []
        for user in users:
            rcpt_addr = f"{user}@{domain}" if domain else user
            try:
                with SmtpSocketSession(
                    self._host, port, self._timeout
                ) as session:
                    session.read_banner()
                    session.send_command("EHLO test.local")
                    session.send_command(f"MAIL FROM:<{mail_from}>")
                    resp = session.send_command(f"RCPT TO:<{rcpt_addr}>")
                    results.append((user, resp))
                    session.send_command("RSET")
            except Exception as exc:
                results.append((user, f"ERROR: {exc}"))
        # Write aggregate session log
        if session_log:
            log_lines = [f"# RCPT TO enumeration against {self._host}:{port}"]
            for user, resp in results:
                log_lines.append(f"RCPT TO:<{user}@{domain}> => {resp}")
            session_log.parent.mkdir(parents=True, exist_ok=True)
            session_log.write_text("\n".join(log_lines) + "\n", encoding="utf-8")
        return results

    def run_relay_test(
        self,
        port: int,
        mail_from: str,
        rcpt_to: str,
        session_log: Path | None = None,
    ) -> dict:
        """
        In safe mode: issue MAIL FROM + RCPT TO only; do NOT send DATA.
        Returns dict with mail_from_code, rcpt_to_code, accepted.
        """
        result: dict = {
            "mail_from_code": 0,
            "mail_from_resp": "",
            "rcpt_to_code": 0,
            "rcpt_to_resp": "",
            "accepted": False,
            "error": "",
        }
        try:
            with SmtpSocketSession(
                self._host, port, self._timeout, session_log
            ) as session:
                session.read_banner()
                session.send_command("EHLO test.local")
                mf_resp = session.send_command(f"MAIL FROM:<{mail_from}>")
                mf_code = int(mf_resp[:3]) if mf_resp[:3].isdigit() else 0
                result["mail_from_code"] = mf_code
                result["mail_from_resp"] = mf_resp

                if mf_code == 250:
                    rcpt_resp = session.send_command(f"RCPT TO:<{rcpt_to}>")
                    rcpt_code = int(rcpt_resp[:3]) if rcpt_resp[:3].isdigit() else 0
                    result["rcpt_to_code"] = rcpt_code
                    result["rcpt_to_resp"] = rcpt_resp
                    result["accepted"] = rcpt_code == 250
                    session.send_command("RSET")
        except Exception as exc:
            result["error"] = str(exc)
        return result

    def run_spoof_test(
        self,
        port: int,
        forged_from: str,
        rcpt_to: str,
        session_log: Path | None = None,
    ) -> dict:
        """
        Issue MAIL FROM with a forged address. Safe mode: no DATA sent.
        """
        return self.run_relay_test(port, forged_from, rcpt_to, session_log)
