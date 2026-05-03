from __future__ import annotations

from abc import ABC, abstractmethod

from ..context import ScanContext


class Reporter(ABC):
    """Abstract base class for all reporters."""

    @abstractmethod
    def write(self, context: ScanContext) -> None:
        """Write a report based on the current scan context."""
        ...
