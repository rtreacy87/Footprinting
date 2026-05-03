from __future__ import annotations

import uuid

from ..models import Evidence


class EvidenceStore:
    """Manages a collection of Evidence objects with ID generation."""

    def __init__(self) -> None:
        self._store: dict[str, Evidence] = {}

    @staticmethod
    def generate_id() -> str:
        return f"EVID-{str(uuid.uuid4())[:8].upper()}"

    def add(self, evidence: Evidence) -> str:
        """Add evidence to the store. Returns the evidence_id."""
        self._store[evidence.evidence_id] = evidence
        return evidence.evidence_id

    def get(self, evidence_id: str) -> Evidence | None:
        return self._store.get(evidence_id)

    def all(self) -> list[Evidence]:
        return list(self._store.values())

    def __len__(self) -> int:
        return len(self._store)
