from __future__ import annotations
from pydantic import BaseModel, Field


class Finding(BaseModel):
    id: str
    title: str
    severity: str
    category: str
    description: str
    evidence: list[str] = Field(default_factory=list)
    source_tool: str
    raw_artifact_path: str | None = None
    recommended_next_steps: list[str] = Field(default_factory=list)
