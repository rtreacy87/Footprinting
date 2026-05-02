from __future__ import annotations

from typing import Any


class AnalyzerRegistry:
    def __init__(self) -> None:
        self._items: dict[str, Any] = {}

    def register(self, name: str, analyzer: Any) -> None:
        self._items[name] = analyzer

    def all_items(self) -> list[tuple[str, Any]]:
        return list(self._items.items())

    def get(self, name: str) -> Any:
        return self._items[name]
