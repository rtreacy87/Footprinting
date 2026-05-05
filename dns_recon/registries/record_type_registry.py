from __future__ import annotations

from dataclasses import dataclass


@dataclass
class RecordTypeSpec:
    record_type: str
    description: str
    pivot_category: str | None = None
    security_relevant: bool = False


RECORD_TYPE_REGISTRY: dict[str, RecordTypeSpec] = {
    "A": RecordTypeSpec("A", "IPv4 address", pivot_category="internal"),
    "AAAA": RecordTypeSpec("AAAA", "IPv6 address", pivot_category="internal"),
    "MX": RecordTypeSpec("MX", "Mail exchange", pivot_category="smtp", security_relevant=True),
    "NS": RecordTypeSpec("NS", "Name server", security_relevant=True),
    "TXT": RecordTypeSpec("TXT", "Text record", security_relevant=True),
    "SOA": RecordTypeSpec("SOA", "Start of authority"),
    "CNAME": RecordTypeSpec("CNAME", "Canonical name alias"),
    "PTR": RecordTypeSpec("PTR", "Reverse DNS pointer"),
    "SRV": RecordTypeSpec("SRV", "Service locator", security_relevant=True),
    "CAA": RecordTypeSpec("CAA", "Certificate authority authorization"),
    "DMARC": RecordTypeSpec("DMARC", "DMARC policy", security_relevant=True),
}

BASELINE_RECORD_TYPES = ["A", "AAAA", "MX", "NS", "TXT", "SOA", "CNAME"]
