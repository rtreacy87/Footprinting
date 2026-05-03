from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Any


class Parser(ABC):
    """Abstract base class for all output parsers."""

    @abstractmethod
    def parse(self, raw_output: str) -> list[Any]:
        """Parse raw tool output and return a list of structured objects."""
        ...
