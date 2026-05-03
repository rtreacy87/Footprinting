from __future__ import annotations

from typing import Type

from .file_classifier import FileClassifier

CLASSIFIER_REGISTRY: dict[str, Type[FileClassifier]] = {}


def register_classifier(cls: Type[FileClassifier]) -> Type[FileClassifier]:
    """Class decorator to register a classifier using its ``name`` attribute."""
    CLASSIFIER_REGISTRY[cls.name] = cls  # type: ignore[attr-defined]
    return cls


# Trigger registration decorators
from . import credential_classifier  # noqa: F401, E402
from . import config_classifier  # noqa: F401, E402
from . import script_classifier  # noqa: F401, E402
from . import backup_classifier  # noqa: F401, E402
