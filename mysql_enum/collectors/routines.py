"""Views, routines, triggers, and events collector."""

from __future__ import annotations

from ..queries import QueryRunner


class RoutinesCollector:
    def __init__(self, runner: QueryRunner) -> None:
        self._runner = runner

    def collect(self) -> dict:
        return {
            "views": self._collect_views(),
            "routines": self._collect_routines(),
            "triggers": self._collect_triggers(),
            "events": self._collect_events(),
        }

    def _collect_views(self) -> list[dict]:
        result = self._runner.run(
            "views",
            "SELECT table_schema, table_name, view_definition, security_type, definer "
            "FROM information_schema.views",
        )
        return result.rows if result.success else []

    def _collect_routines(self) -> list[dict]:
        result = self._runner.run(
            "routines",
            "SELECT routine_schema, routine_name, routine_type, security_type, definer "
            "FROM information_schema.routines",
        )
        return result.rows if result.success else []

    def _collect_triggers(self) -> list[dict]:
        result = self._runner.run(
            "triggers",
            "SELECT trigger_schema, trigger_name, event_object_table, "
            "action_timing, event_manipulation, definer "
            "FROM information_schema.triggers",
        )
        return result.rows if result.success else []

    def _collect_events(self) -> list[dict]:
        result = self._runner.run(
            "events",
            "SELECT event_schema, event_name, definer, status, event_type "
            "FROM information_schema.events",
        )
        return result.rows if result.success else []
