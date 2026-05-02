from __future__ import annotations

from typing import Any


class EnumeratorRegistry:
    """Registry of named enumerators. Extension point — add new enumerators without changing orchestration."""

    def __init__(self) -> None:
        self._items: dict[str, Any] = {}
        self._enabled: dict[str, bool] = {}

    def register(self, name: str, enumerator: Any, enabled: bool = True) -> None:
        self._items[name] = enumerator
        self._enabled[name] = enabled

    def enable(self, name: str) -> None:
        self._enabled[name] = True

    def disable(self, name: str) -> None:
        self._enabled[name] = False

    def enabled_items(self) -> list[tuple[str, Any]]:
        return [(name, item) for name, item in self._items.items() if self._enabled.get(name, True)]

    def get(self, name: str) -> Any:
        return self._items[name]

    def names(self) -> list[str]:
        return list(self._items.keys())
