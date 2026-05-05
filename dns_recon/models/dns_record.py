from __future__ import annotations

from dataclasses import dataclass


@dataclass
class DnsRecord:
    fqdn: str
    record_type: str
    value: str
    source: str = "dig"
    zone: str | None = None

    def to_dict(self) -> dict:
        return {
            "fqdn": self.fqdn,
            "record_type": self.record_type,
            "value": self.value,
            "source": self.source,
            "zone": self.zone,
        }
