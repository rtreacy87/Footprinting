"""Configuration models for mssql_enum."""

from __future__ import annotations

from datetime import datetime
from pathlib import Path
from typing import Literal

from pydantic import BaseModel, SecretStr, field_validator


class TargetConfig(BaseModel):
    target: str
    port: int = 1433
    username: str | None = None
    password: SecretStr | None = None
    auth_mode: Literal["sql", "windows", "no-auth"] = "sql"
    domain: str | None = None
    timeout_seconds: int = 10
    output_dir: Path
    safe_mode: bool = True

    @field_validator("port")
    @classmethod
    def _valid_port(cls, v: int) -> int:
        if not 1 <= v <= 65535:
            raise ValueError(f"Invalid port: {v}")
        return v

    @property
    def target_dir(self) -> Path:
        return self.output_dir / "mssql" / self.target

    @property
    def password_value(self) -> str | None:
        if self.password is None:
            return None
        return self.password.get_secret_value()


class QueryResult(BaseModel):
    query_name: str
    sql: str
    success: bool
    rows: list[dict] = []
    error: str | None = None
    started_at: datetime
    finished_at: datetime


class Finding(BaseModel):
    id: str
    severity: Literal["critical", "high", "medium", "low", "info"]
    category: str
    title: str
    description: str
    evidence: dict = {}
    recommended_manual_check: str | None = None
