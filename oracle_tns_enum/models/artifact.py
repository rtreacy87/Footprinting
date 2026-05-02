from __future__ import annotations
from pydantic import BaseModel


class Artifact(BaseModel):
    name: str
    path: str
    artifact_type: str  # "raw" | "parsed"
    tool: str
