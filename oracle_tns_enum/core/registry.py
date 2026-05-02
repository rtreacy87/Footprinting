from __future__ import annotations
from typing import Any


class Registry:
    def __init__(self) -> None:
        self._items: dict[str, Any] = {}

    def register(self, name: str, item: Any) -> None:
        self._items[name] = item

    def get(self, name: str) -> Any:
        return self._items[name]

    def all_names(self) -> list[str]:
        return list(self._items.keys())

    def all_items(self) -> list[Any]:
        return list(self._items.values())

    def __contains__(self, name: str) -> bool:
        return name in self._items
