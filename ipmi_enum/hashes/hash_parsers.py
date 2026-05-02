from __future__ import annotations

import re
from dataclasses import dataclass

from ..models import CredentialFinding, HashFinding


@dataclass
class ParsedHash:
    username: str
    raw_hash: str
    cracked_password: str | None = None
    hashcat_line: str | None = None


class MsfDumpHashesParser:
    """
    Parses Metasploit ipmi_dumphashes output.

    Typical MSF output lines:
      [+] 10.129.202.5 - IPMI - Hash found: admin:...long hash...
      [+] 10.129.202.5 - IPMI - Hash for user 'admin' matches dictionary password 'password123'
      [*] Scanned 1 of 1 hosts (100% complete)
    """

    _HASH_LINE_RE = re.compile(
        r"\[\+\]\s+\S+\s+-\s+IPMI\s+-\s+Hash found:\s*(\w+):(\S+)",
        re.IGNORECASE,
    )
    _CRACKED_RE = re.compile(
        r"\[\+\]\s+\S+\s+-\s+IPMI\s+-\s+"
        r"Hash for user ['\"]?(\w+)['\"]? matches dictionary password ['\"]?([^'\"]+)['\"]?",
        re.IGNORECASE,
    )
    # Alternative cracked format: "... - Found plaintext password ..."
    _CRACKED_ALT_RE = re.compile(
        r"\[\+\]\s+\S+\s+-\s+.*?Found plaintext password\s+for\s+(\w+):\s*(\S+)",
        re.IGNORECASE,
    )
    # Some MSF versions just print: username:password after cracking
    _SIMPLE_CRACKED_RE = re.compile(
        r"\[\+\]\s+\S+\s+\d+\s+-\s+IPMI\s+-\s+(\w+):([^\s:]+)\s+\(cracked\)",
        re.IGNORECASE,
    )

    def parse(self, output: str, target: str) -> list[ParsedHash]:
        results: dict[str, ParsedHash] = {}

        for line in output.splitlines():
            m = self._HASH_LINE_RE.search(line)
            if m:
                username = m.group(1)
                raw_hash = m.group(2)
                if username not in results:
                    results[username] = ParsedHash(username=username, raw_hash=raw_hash)
                else:
                    results[username].raw_hash = raw_hash

            m = self._CRACKED_RE.search(line)
            if m:
                username = m.group(1)
                password = m.group(2)
                if username in results:
                    results[username].cracked_password = password
                else:
                    results[username] = ParsedHash(username=username, raw_hash="", cracked_password=password)

            m = self._CRACKED_ALT_RE.search(line)
            if m:
                username = m.group(1)
                password = m.group(2)
                if username in results:
                    results[username].cracked_password = password
                else:
                    results[username] = ParsedHash(username=username, raw_hash="", cracked_password=password)

            m = self._SIMPLE_CRACKED_RE.search(line)
            if m:
                username = m.group(1)
                password = m.group(2)
                if username in results:
                    results[username].cracked_password = password
                else:
                    results[username] = ParsedHash(username=username, raw_hash="", cracked_password=password)

        return list(results.values())

    def to_findings(self, parsed: list[ParsedHash], target: str) -> tuple[list[HashFinding], list[CredentialFinding]]:
        hashes = []
        creds = []
        for p in parsed:
            hashes.append(HashFinding(
                target=target,
                username=p.username,
                raw_hash=p.raw_hash,
                cracked_password=p.cracked_password,
            ))
            if p.cracked_password:
                creds.append(CredentialFinding(
                    target=target,
                    username=p.username,
                    password=p.cracked_password,
                    status="cracked",
                    source="msf_ipmi_dumphashes",
                    raw_hash=p.raw_hash,
                ))
            else:
                creds.append(CredentialFinding(
                    target=target,
                    username=p.username,
                    password=None,
                    status="hash_only",
                    source="msf_ipmi_dumphashes",
                    raw_hash=p.raw_hash,
                ))
        return hashes, creds


def parse_msf_dumphashes(output: str, target: str) -> tuple[list[HashFinding], list[CredentialFinding]]:
    parser = MsfDumpHashesParser()
    parsed = parser.parse(output, target)
    return parser.to_findings(parsed, target)
