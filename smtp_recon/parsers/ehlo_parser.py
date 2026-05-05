from __future__ import annotations

import re
from dataclasses import dataclass, field

from ..models.smtp_capability import SmtpCapability
from .base import BaseParser
from .smtp_response_parser import SmtpResponseParser


@dataclass
class EhloResult:
    greeting: str
    capabilities: list[SmtpCapability] = field(default_factory=list)
    auth_methods: list[str] = field(default_factory=list)
    starttls: bool = False
    size_limit: int = 0
    raw: str = ""


class EhloParser(BaseParser):
    """Parse a 250-response from EHLO into structured capabilities."""

    def parse(self, raw: str) -> EhloResult:
        result = EhloResult(raw=raw, greeting="")
        parser = SmtpResponseParser()
        lines = parser.parse(raw)

        for i, line in enumerate(lines):
            if line.code != 250:
                continue
            if i == 0:
                result.greeting = line.text
                continue

            text = line.text.strip()
            parts = text.split()
            if not parts:
                continue

            keyword = parts[0].upper()
            params = parts[1:]

            # Skip the bare 'OK' that some servers append as the final line text
            if keyword == "OK" and not params:
                continue

            cap = SmtpCapability(keyword=keyword, parameters=params)
            result.capabilities.append(cap)

            if keyword == "STARTTLS":
                result.starttls = True
            elif keyword == "AUTH":
                result.auth_methods = [m.upper() for m in params]
            elif keyword == "SIZE" and params:
                try:
                    result.size_limit = int(params[0])
                except ValueError:
                    pass

        return result
