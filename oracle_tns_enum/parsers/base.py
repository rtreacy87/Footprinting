from __future__ import annotations
from abc import ABC, abstractmethod


class BaseParser(ABC):
    name: str = ""

    @abstractmethod
    def parse(self, raw_text: str) -> dict:
        raise NotImplementedError
