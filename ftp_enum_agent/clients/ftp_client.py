"""Low-level FTP client implementing connection, auth, listing, download, and upload.

Protocols (Interface Segregation) allow enumerators to depend only on the
capability they need rather than the full concrete client.
"""
from __future__ import annotations

import posixpath
import re
import select
import socket
import time
from io import BytesIO
from typing import Iterator, Protocol, Set

from ..models import FileEntry


# ---------------------------------------------------------------------------
# Path helpers
# ---------------------------------------------------------------------------

def normalize_remote_path(path: str) -> str:
    if not path:
        return "/"
    normalized = posixpath.normpath(path)
    return normalized if normalized.startswith("/") else f"/{normalized}"


def join_remote_path(parent: str, name: str) -> str:
    if parent == "/":
        return normalize_remote_path(f"/{name}")
    return normalize_remote_path(posixpath.join(parent, name))


def parse_list_line(directory: str, line: str) -> FileEntry | None:
    """Parse a single Unix-style LIST output line into a FileEntry."""
    parts = line.split(maxsplit=8)
    if len(parts) < 9:
        return None
    name = parts[8]
    if name in {".", ".."}:
        return None

    is_dir = line.startswith("d")
    size: int | None = None
    try:
        size = int(parts[4])
    except (ValueError, IndexError):
        pass

    modified = " ".join(parts[5:8]) if len(parts) >= 8 else None
    permissions = parts[0] if parts else None
    owner = parts[2] if len(parts) > 2 else None

    return FileEntry(
        name=name,
        path=join_remote_path(directory, name),
        is_dir=is_dir,
        size=size,
        modified=modified,
        permissions=permissions,
        owner=owner,
    )


# ---------------------------------------------------------------------------
# Capability protocols (Interface Segregation)
# ---------------------------------------------------------------------------

class ConnectableClient(Protocol):
    def connect(self) -> str: ...
    def close(self) -> None: ...


class AuthenticatableClient(Protocol):
    def login(self, username: str, password: str) -> None: ...


class ListableClient(Protocol):
    def list_entries(self, path: str) -> Iterator[FileEntry]: ...
    def get_features(self) -> str: ...
    def get_system(self) -> str: ...


class DownloadableClient(Protocol):
    def retrieve_bytes(self, path: str) -> bytes: ...
    def retrieve_text(self, path: str) -> str: ...


class UploadableClient(Protocol):
    def upload_bytes(self, path: str, data: bytes) -> bool: ...


# ---------------------------------------------------------------------------
# Concrete FTP client
# ---------------------------------------------------------------------------

class FTPClient:
    """Raw-socket FTP client implementing all capability protocols."""

    def __init__(self, host: str, port: int = 21, timeout: float = 10.0, idle_gap: float = 0.6) -> None:
        self.host = host
        self.port = port
        self.timeout = timeout
        self.idle_gap = idle_gap
        self._sock: socket.socket | None = None

    # -- ConnectableClient --------------------------------------------------

    def connect(self) -> str:
        """Connect and return the server banner."""
        self._sock = socket.create_connection((self.host, self.port), timeout=self.timeout)
        self._send_raw("\r\n")
        response = self._read_until_codes({220})
        banner = self._extract_code_line(response, 220)
        if banner is None:
            raise ConnectionError("FTP banner not received")
        return banner

    def close(self) -> None:
        if self._sock is None:
            return
        try:
            self.command("QUIT", expect_codes={221})
        except Exception:
            pass
        finally:
            self._sock.close()
            self._sock = None

    # -- AuthenticatableClient ---------------------------------------------

    def login(self, username: str, password: str) -> None:
        user_resp = self.command(f"USER {username}", expect_codes={230, 331})
        if self._extract_code_line(user_resp, 230) is not None:
            return
        pass_resp = self.command(f"PASS {password}", expect_codes={230})
        if self._extract_code_line(pass_resp, 230) is None:
            raise PermissionError(f"FTP login failed for user '{username}'")

    # -- ListableClient ----------------------------------------------------

    def list_entries(self, path: str = "/") -> Iterator[FileEntry]:
        target = normalize_remote_path(path)
        cmd = "LIST" if target == "/" else f"LIST {target}"
        listing = self._transfer_text(cmd)
        for line in listing.splitlines():
            entry = parse_list_line(target, line.strip())
            if entry is not None:
                yield entry

    def get_features(self) -> str:
        try:
            return self.command("FEAT", expect_codes={211, 500, 502})
        except Exception:
            return ""

    def get_system(self) -> str:
        try:
            return self.command("SYST", expect_codes={215, 500, 502})
        except Exception:
            return ""

    # -- DownloadableClient ------------------------------------------------

    def retrieve_bytes(self, path: str) -> bytes:
        return self._transfer_binary(f"RETR {normalize_remote_path(path)}")

    def retrieve_text(self, path: str) -> str:
        return self._transfer_text(f"RETR {normalize_remote_path(path)}").strip()

    # -- UploadableClient --------------------------------------------------

    def upload_bytes(self, path: str, data: bytes) -> bool:
        """Upload bytes to a remote path. Returns True on success."""
        try:
            host, port = self._enter_passive_mode()
            with socket.create_connection((host, port), timeout=self.timeout) as data_sock:
                self._send_raw(f"STOR {normalize_remote_path(path)}\r\n")
                self._read_until_codes({125, 150})
                data_sock.sendall(data)
            self._read_until_codes({226, 250})
            return True
        except Exception:
            return False

    # -- Low-level transport -----------------------------------------------

    def command(self, cmd: str, expect_codes: Set[int]) -> str:
        self._send_raw(f"{cmd}\r\n")
        return self._read_until_codes(expect_codes)

    def _transfer_text(self, cmd: str) -> str:
        host, port = self._enter_passive_mode()
        with socket.create_connection((host, port), timeout=self.timeout) as data_sock:
            self._send_raw(f"{cmd}\r\n")
            self._read_until_codes({125, 150})
            payload = self._read_available(data_sock, self.timeout).decode("utf-8", errors="replace")
        self._read_until_codes({226, 250})
        return payload

    def _transfer_binary(self, cmd: str) -> bytes:
        host, port = self._enter_passive_mode()
        with socket.create_connection((host, port), timeout=self.timeout) as data_sock:
            self._send_raw(f"{cmd}\r\n")
            self._read_until_codes({125, 150})
            payload = self._read_available(data_sock, self.timeout)
        self._read_until_codes({226, 250})
        return payload

    def _enter_passive_mode(self) -> tuple[str, int]:
        response = self.command("PASV", expect_codes={227})
        match = re.search(r"\((\d+),(\d+),(\d+),(\d+),(\d+),(\d+)\)", response)
        if match is None:
            raise ConnectionError("PASV response missing data endpoint")
        host = ".".join(match.groups()[:4])
        port = int(match.group(5)) * 256 + int(match.group(6))
        return host, port

    def _read_until_codes(self, expect_codes: Set[int]) -> str:
        if self._sock is None:
            raise RuntimeError("Not connected")
        deadline = time.time() + self.timeout
        chunks: list[str] = []
        while time.time() < deadline:
            chunk = self._read_available(self._sock, deadline - time.time()).decode("utf-8", errors="replace")
            if chunk:
                chunks.append(chunk)
                combined = "".join(chunks)
                if any(self._extract_code_line(combined, code) is not None for code in expect_codes):
                    return combined
        combined = "".join(chunks)
        raise TimeoutError(f"Timed out waiting for FTP codes {sorted(expect_codes)}: {combined!r}")

    def _read_available(self, sock: socket.socket, max_wait: float) -> bytes:
        deadline = time.time() + max_wait
        chunks: list[bytes] = []
        seen_data = False
        while time.time() < deadline:
            timeout = self.idle_gap if seen_data else deadline - time.time()
            if timeout <= 0:
                break
            readable, _, _ = select.select([sock], [], [], timeout)
            if not readable:
                if seen_data:
                    break
                continue
            data = sock.recv(4096)
            if not data:
                break
            chunks.append(data)
            seen_data = True
        return b"".join(chunks)

    def _send_raw(self, data: str) -> None:
        if self._sock is None:
            raise RuntimeError("Not connected")
        self._sock.sendall(data.encode("ascii"))

    @staticmethod
    def _extract_code_line(response: str, code: int) -> str | None:
        prefix = f"{code} "
        for line in response.splitlines():
            if line.startswith(prefix):
                return line.strip()
        return None
