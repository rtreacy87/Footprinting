"""Table classification for risk scoring."""

from __future__ import annotations

from ..utils.identifiers import is_system_database


def classify_tables(tables: list[dict]) -> dict:
    system_tables = []
    application_tables = []
    for t in tables:
        schema = t.get("table_schema", "")
        if is_system_database(schema):
            system_tables.append(t)
        else:
            application_tables.append(t)
    return {
        "system": system_tables,
        "application": application_tables,
        "application_count": len(application_tables),
        "system_count": len(system_tables),
    }
