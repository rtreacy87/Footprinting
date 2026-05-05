from __future__ import annotations

import re

from ..models.dns_record import DnsRecord
from .base import BaseParser

_AXFR_RECORD = re.compile(
    r"^(\S+)\s+\d+\s+IN\s+(\w+)\s+(.+)$",
    re.MULTILINE,
)
_TRANSFER_FAILED = re.compile(
    r"Transfer failed|REFUSED|no transfer|connection refused|timed out|SERVFAIL|communications error",
    re.IGNORECASE,
)


class ZoneTransferParser(BaseParser):
    def parse(self, raw_output: str, zone: str | None = None) -> list[DnsRecord]:
        records: list[DnsRecord] = []
        for match in _AXFR_RECORD.finditer(raw_output):
            fqdn = match.group(1).rstrip(".").lower()
            rtype = match.group(2).upper()
            value = match.group(3).strip()
            if rtype in ("CNAME", "NS", "MX", "SOA", "PTR"):
                value = value.rstrip(".")
            if rtype == "TXT":
                value = value.strip('"')
            records.append(DnsRecord(fqdn=fqdn, record_type=rtype, value=value, source="axfr", zone=zone))
        return records

    def classify_result(self, raw_output: str, returncode: int, timed_out: bool) -> str:
        if timed_out:
            return "timeout"
        if returncode != 0 and not raw_output.strip():
            return "error"
        if _TRANSFER_FAILED.search(raw_output):
            return "refused"
        if raw_output.strip():
            lines = [l for l in raw_output.splitlines() if l.strip() and not l.startswith(";")]
            if len(lines) > 2:
                return "success"
        return "failure"
