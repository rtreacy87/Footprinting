from __future__ import annotations
from pydantic import BaseModel


class Credential(BaseModel):
    username: str
    password: str
    sid: str | None = None
    service_name: str | None = None
    source: str
    valid: bool = False
    has_dba: bool = False
