"""Configuration models for mysql_enum."""

from __future__ import annotations

from datetime import datetime
from pathlib import Path
from typing import Literal

from pydantic import BaseModel, SecretStr, field_validator


class TargetConfig(BaseModel):
    target: str
    port: int = 3306
    username: str | None = None
    password: SecretStr | None = None
    database: str | None = None
    ssl_mode: str = "preferred"
    timeout_seconds: int = 10
    output_dir: Path
    safe_mode: bool = True
    sample_rows: int = 20
    preserve_sensitive: bool = False

    @field_validator("port")
    @classmethod
    def _valid_port(cls, v: int) -> int:
        if not 1 <= v <= 65535:
            raise ValueError(f"Invalid port: {v}")
        return v

    @property
    def target_dir(self) -> Path:
        return self.output_dir / "mysql" / self.target

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
    severity: Literal["critical", "high", "medium", "low", "info"]
    title: str
    description: str
    evidence: dict
    recommendation: str | None = None


class RunMetadata(BaseModel):
    target: str
    port: int
    started_at: str
    mode: str
    package_version: str = "0.1.0"
    safe_mode: bool = True
    username: str | None = None
    password_supplied: bool = False
