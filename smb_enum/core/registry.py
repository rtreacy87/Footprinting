from __future__ import annotations

from typing import Generic, Iterator, TypeVar

T = TypeVar("T")


class Registry(Generic[T]):
    """Generic key-to-class registry."""

    def __init__(self) -> None:
        self._items: dict[str, T] = {}

    def register(self, key: str, cls: T) -> None:
        self._items[key] = cls

    def get(self, key: str) -> T | None:
        return self._items.get(key)

    def require(self, key: str) -> T:
        if key not in self._items:
            raise KeyError(f"No item registered under '{key}'")
        return self._items[key]

    def keys(self) -> list[str]:
        return list(self._items.keys())

    def items(self) -> Iterator[tuple[str, T]]:
        return iter(self._items.items())

    def __contains__(self, key: str) -> bool:
        return key in self._items
