from __future__ import annotations

from typing import Generic, TypeVar

T = TypeVar("T")


class Registry(Generic[T]):
    def __init__(self) -> None:
        self._items: dict[str, T] = {}
        self._capabilities: dict[str, list[str]] = {}

    def register(self, name: str, capabilities: list[str] | None = None):
        def decorator(cls: T) -> T:
            self._items[name] = cls
            if capabilities:
                for cap in capabilities:
                    self._capabilities.setdefault(cap, []).append(name)
            return cls
        return decorator

    def get(self, name: str) -> T:
        if name not in self._items:
            raise KeyError(f"No item registered under '{name}'")
        return self._items[name]

    def by_capability(self, capability: str) -> list[T]:
        names = self._capabilities.get(capability, [])
        return [self._items[n] for n in names if n in self._items]

    def all_names(self) -> list[str]:
        return list(self._items.keys())

    def all_items(self) -> list[T]:
        return list(self._items.values())

    def __contains__(self, name: str) -> bool:
        return name in self._items
