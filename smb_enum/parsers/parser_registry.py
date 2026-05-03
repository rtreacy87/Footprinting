from __future__ import annotations

from typing import Type

from .parser import Parser

PARSER_REGISTRY: dict[str, Type[Parser]] = {}


def register_parser(key: str):
    """Decorator to register a parser class under a given key."""
    def decorator(cls: Type[Parser]) -> Type[Parser]:
        PARSER_REGISTRY[key] = cls
        return cls
    return decorator


# Populate registry by importing all parser modules
from . import nmap_parsers  # noqa: E402, F401
from . import smbclient_parsers  # noqa: E402, F401
from . import smbmap_parsers  # noqa: E402, F401
from . import rpcclient_parsers  # noqa: E402, F401
from . import enum4linux_parsers  # noqa: E402, F401
