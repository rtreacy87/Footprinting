from __future__ import annotations
from pydantic import BaseModel, Field


class OracleService(BaseModel):
    host: str
    port: int
    listener_version: str | None = None
    sids: list[str] = Field(default_factory=list)
    service_names: list[str] = Field(default_factory=list)
    requires_authentication: bool | None = None
