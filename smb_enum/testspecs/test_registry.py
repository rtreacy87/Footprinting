from __future__ import annotations

from typing import Type

from .base_test import BaseTest

TEST_REGISTRY: dict[str, Type[BaseTest]] = {}


def register_test(cls: Type[BaseTest]) -> Type[BaseTest]:
    """Class decorator that adds the test to TEST_REGISTRY using its test_id."""
    TEST_REGISTRY[cls.test_id] = cls
    return cls
