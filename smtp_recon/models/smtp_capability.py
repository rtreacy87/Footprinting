from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class SmtpCapability:
    keyword: str
    parameters: list[str] = field(default_factory=list)

    def __str__(self) -> str:
        if self.parameters:
            return f"{self.keyword} {' '.join(self.parameters)}"
        return self.keyword
