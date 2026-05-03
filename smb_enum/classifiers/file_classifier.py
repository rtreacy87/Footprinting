from __future__ import annotations

from abc import ABC, abstractmethod

from ..models import FileMetadata, FileFinding


class FileClassifier(ABC):
    """Abstract base class for file classifiers."""

    @abstractmethod
    def classify(self, file_metadata: FileMetadata) -> list[FileFinding]:
        """Classify a file and return zero or more FileFinding objects."""
        ...
