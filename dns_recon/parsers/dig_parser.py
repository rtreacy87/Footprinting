from __future__ import annotations

import re

from ..models.dns_record import DnsRecord
from .base import BaseParser

_RECORD_LINE = re.compile(
    r"^(\S+)\s+\d+\s+IN\s+(\w+)\s+(.+)$",
    re.MULTILINE,
)
_CHAOS_LINE = re.compile(
    r"^(\S+)\s+\d+\s+CHAOS\s+(\w+)\s+(.+)$",
    re.MULTILINE,
)


class DigParser(BaseParser):
    def parse(self, raw_output: str, source: str = "dig", zone: str | None = None) -> list[DnsRecord]:
        records: list[DnsRecord] = []
        for match in _RECORD_LINE.finditer(raw_output):
            fqdn = match.group(1).rstrip(".").lower()
            rtype = match.group(2).upper()
            value = match.group(3).strip()
            if rtype == "CNAME" or rtype == "NS" or rtype == "MX" or rtype == "SOA":
                value = value.rstrip(".")
            records.append(DnsRecord(fqdn=fqdn, record_type=rtype, value=value, source=source, zone=zone))
        for match in _CHAOS_LINE.finditer(raw_output):
            fqdn = match.group(1).rstrip(".").lower()
            rtype = match.group(2).upper()
            value = match.group(3).strip().strip('"')
            records.append(DnsRecord(fqdn=fqdn, record_type=rtype, value=value, source="dig-chaos", zone=zone))
        return records
