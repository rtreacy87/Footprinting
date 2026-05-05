from __future__ import annotations

import logging
from pathlib import Path

from ..models.scan_context import ScanContext

logger = logging.getLogger(__name__)

_SUBDIRS = [
    "metadata",
    "raw/nmap",
    "raw/manual_sessions",
    "raw/swaks",
    "normalized",
    "trust_boundary_tests/open_relay",
    "trust_boundary_tests/spoofing",
    "identity_enumeration",
    "security_controls",
    "failures_and_dead_ends",
    "findings",
    "agent_inputs",
    "report",
]


def create_output_tree(context: ScanContext) -> None:
    """Create the full directory tree under context.target_dir."""
    for subdir in _SUBDIRS:
        path = context.target_dir / subdir
        path.mkdir(parents=True, exist_ok=True)
    logger.info("[output_tree] Created directory tree at %s", context.target_dir)
