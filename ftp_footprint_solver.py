#!/usr/bin/env python3

import argparse
import posixpath
import re
import select
import socket
import sys
import time
from dataclasses import dataclass
from typing import Iterable, List, Optional, Set, Tuple


@dataclass(frozen=True)
class FtpEntry:
    name: str
    path: str
    is_dir: bool


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Solve the HTB FTP footprinting lab by grabbing the banner and flag.txt."
    )
    parser.add_argument("host", help="Target IP or hostname")
    parser.add_argument("--port", type=int, default=21, help="FTP port (default: 21)")
    parser.add_argument("--user", default="anonymous", help="FTP username (default: anonymous)")
    parser.add_argument("--password", default="anonymous", help="FTP password (default: anonymous)")
    parser.add_argument("--timeout", type=float, default=10.0, help="Socket timeout in seconds")
    parser.add_argument("--idle-gap", type=float, default=0.6, help="Idle read gap in seconds")
    return parser.parse_args()


def normalize_remote_path(path: str) -> str:
    if not path:
        return "/"
    normalized = posixpath.normpath(path)
    return normalized if normalized.startswith("/") else f"/{normalized}"


def join_remote_path(parent: str, name: str) -> str:
    if parent == "/":
        return normalize_remote_path(f"/{name}")
    return normalize_remote_path(posixpath.join(parent, name))


def parse_list_line(path: str, line: str) -> Optional[FtpEntry]:
    parts = line.split(maxsplit=8)
    if len(parts) < 9:
        return None

    name = parts[8]
    if name in {".", ".."}:
        return None

    return FtpEntry(name=name, path=join_remote_path(path, name), is_dir=line.startswith("d"))


class RawFtpClient:
    def __init__(self, host: str, port: int, timeout: float, idle_gap: float) -> None:
        self.host = host
        self.port = port
        self.timeout = timeout
        self.idle_gap = idle_gap
        self.sock: Optional[socket.socket] = None

    def connect(self) -> str:
        self.sock = socket.create_connection((self.host, self.port), timeout=self.timeout)
        self._send_raw("\r\n")
        response = self._read_until_codes({220})
        banner = self._extract_code_line(response, 220)
        if banner is None:
            raise TimeoutError("FTP banner was not received")
        return banner

    def login(self, username: str, password: str) -> None:
        user_response = self.command(f"USER {username}", expect_codes={230, 331})
        if self._extract_code_line(user_response, 230) is not None:
            return

        pass_response = self.command(f"PASS {password}", expect_codes={230})
        if self._extract_code_line(pass_response, 230) is None:
            raise RuntimeError("FTP login failed")

    def list_entries(self, path: str) -> Iterable[FtpEntry]:
        target = normalize_remote_path(path)
        listing = self._transfer_text("LIST" if target == "/" else f"LIST {target}")
        for line in listing.splitlines():
            entry = parse_list_line(target, line.strip())
            if entry is not None:
                yield entry

    def retrieve_text(self, path: str) -> str:
        return self._transfer_text(f"RETR {normalize_remote_path(path)}").strip()

    def close(self) -> None:
        if self.sock is None:
            return
        try:
            self.command("QUIT", expect_codes={221})
        except Exception:
            pass
        finally:
            self.sock.close()
            self.sock = None

    def command(self, command: str, expect_codes: Set[int]) -> str:
        self._send_raw(f"{command}\r\n")
        return self._read_until_codes(expect_codes)

    def _transfer_text(self, command: str) -> str:
        host, port = self._enter_passive_mode()
        with socket.create_connection((host, port), timeout=self.timeout) as data_sock:
            self._send_raw(f"{command}\r\n")
            self._read_until_codes({125, 150})
            payload = self._read_available(data_sock, self.timeout).decode("utf-8", errors="replace")
        self._read_until_codes({226, 250})
        return payload

    def _enter_passive_mode(self) -> Tuple[str, int]:
        response = self.command("PASV", expect_codes={227})
        match = re.search(r"\((\d+),(\d+),(\d+),(\d+),(\d+),(\d+)\)", response)
        if match is None:
            raise RuntimeError("PASV response did not include a data endpoint")
        host = ".".join(match.groups()[:4])
        port = int(match.group(5)) * 256 + int(match.group(6))
        return host, port

    def _read_until_codes(self, expect_codes: Set[int]) -> str:
        if self.sock is None:
            raise RuntimeError("FTP socket is not connected")

        deadline = time.time() + self.timeout
        chunks: List[str] = []

        while time.time() < deadline:
            chunk = self._read_available(self.sock, deadline - time.time()).decode("utf-8", errors="replace")
            if chunk:
                chunks.append(chunk)
                combined = "".join(chunks)
                if any(self._extract_code_line(combined, code) is not None for code in expect_codes):
                    return combined

        combined = "".join(chunks)
        raise TimeoutError(f"Timed out waiting for FTP response codes {sorted(expect_codes)}: {combined!r}")

    def _read_available(self, sock: socket.socket, max_wait: float) -> bytes:
        deadline = time.time() + max_wait
        chunks: List[bytes] = []
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
        if self.sock is None:
            raise RuntimeError("FTP socket is not connected")
        self.sock.sendall(data.encode("ascii"))

    @staticmethod
    def _extract_code_line(response: str, code: int) -> Optional[str]:
        prefix = f"{code} "
        for line in response.splitlines():
            if line.startswith(prefix):
                return line.strip()
        return None


def find_flag(client: RawFtpClient, start_path: str = "/") -> Tuple[str, str]:
    pending = [normalize_remote_path(start_path)]
    visited: Set[str] = set()

    while pending:
        current = pending.pop()
        if current in visited:
            continue
        visited.add(current)

        for entry in client.list_entries(current):
            if entry.is_dir:
                pending.append(entry.path)
                continue

            if entry.name.lower() == "flag.txt":
                return entry.path, client.retrieve_text(entry.path)

    raise FileNotFoundError("flag.txt was not found in the accessible FTP tree")


def main() -> int:
    args = parse_args()
    client = RawFtpClient(args.host, args.port, args.timeout, args.idle_gap)

    try:
        banner = client.connect()
        print(f"Banner: {banner}")
        client.login(args.user, args.password)
        flag_path, flag_value = find_flag(client)
        print(f"Flag path: {flag_path}")
        print(f"Flag: {flag_value}")
        return 0
    except (OSError, RuntimeError, TimeoutError, FileNotFoundError) as exc:
        print(f"FTP solver error: {exc}", file=sys.stderr)
        return 1
    finally:
        client.close()


if __name__ == "__main__":
    sys.exit(main())