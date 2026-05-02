from __future__ import annotations
from pydantic import BaseModel, Field


class Target(BaseModel):
    host: str
    port: int = 1521
    protocol: str = "tcp"
    label: str | None = None
