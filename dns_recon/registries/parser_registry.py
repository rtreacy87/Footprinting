from __future__ import annotations

from ..parsers.base import BaseParser
from ..parsers.dig_parser import DigParser
from ..parsers.nmap_parser import NmapParser
from ..parsers.zone_transfer_parser import ZoneTransferParser

PARSER_REGISTRY: dict[str, type[BaseParser]] = {
    "dig": DigParser,
    "nmap": NmapParser,
    "zone_transfer": ZoneTransferParser,
}


def get_parser(tool_name: str) -> BaseParser:
    cls = PARSER_REGISTRY.get(tool_name)
    if cls is None:
        raise ValueError(f"Unknown parser: {tool_name!r}. Available: {list(PARSER_REGISTRY)}")
    return cls()
