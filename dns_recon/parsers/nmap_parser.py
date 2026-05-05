from __future__ import annotations

import re

from ..models.dns_record import DnsRecord
from .base import BaseParser

_NSID = re.compile(r"dns-nsid:\s*\n\s*bind\.version:\s*(.+)", re.IGNORECASE)
_RECURSION = re.compile(r"dns-recursion:\s*\n\s*Recursion appears to be (enabled|disabled)", re.IGNORECASE)


class NmapParser(BaseParser):
    def parse(self, raw_output: str, zone: str | None = None) -> list[DnsRecord]:
        records: list[DnsRecord] = []
        m = _NSID.search(raw_output)
        if m:
            records.append(DnsRecord(
                fqdn="version.bind",
                record_type="TXT",
                value=m.group(1).strip(),
                source="nmap-nsid",
                zone=zone,
            ))
        m = _RECURSION.search(raw_output)
        if m:
            records.append(DnsRecord(
                fqdn="_recursion",
                record_type="META",
                value=m.group(1).lower(),
                source="nmap-recursion",
                zone=zone,
            ))
        return records
