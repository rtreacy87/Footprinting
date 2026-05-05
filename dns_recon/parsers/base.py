from __future__ import annotations

from abc import ABC, abstractmethod

from ..models.dns_record import DnsRecord


class BaseParser(ABC):
    @abstractmethod
    def parse(self, raw_output: str, **kwargs) -> list[DnsRecord]: ...
