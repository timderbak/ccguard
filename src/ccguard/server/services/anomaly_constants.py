"""Locked constants for Phase 2 anomaly detection.

These constants are the SINGLE source of truth for Phase 2 anomaly aggregators
and downstream UI/diff routines. Do not duplicate string literals elsewhere.

Field paths reflect the public attribute names of the inventory schema
(``ccguard.schemas.inventory``):

* :class:`McpServerEntry.name`     — identity key for MCP servers.
* :class:`AgentEntry.name`         — identity key for custom subagents.
* :class:`AgentEntry.file_hash`    — drives the ``new_agents`` diff signal.
* :class:`SkillEntry.name`         — identity key for skills.
* :class:`SkillEntry.dir_hash`     — drives the ``skill_dir_hash_changes`` diff signal.

The metric tuple lists every per-machine baseline metric persisted in
``MachineBaseline``. Plan 02-01 owns this list; new metrics MUST be appended
here (and not invented ad-hoc in aggregators).
"""

from __future__ import annotations

# --- locked inventory field paths -------------------------------------------

MCP_NAME_FIELD: str = "name"
AGENT_NAME_FIELD: str = "name"
AGENT_HASH_FIELD: str = "file_hash"
SKILL_NAME_FIELD: str = "name"
SKILL_HASH_FIELD: str = "dir_hash"

# --- anomaly metric registry ------------------------------------------------

ALL_METRICS: tuple[str, ...] = (
    "bash_calls_per_day",
    "new_mcp_per_week",
    "new_agents_per_week",
    "skill_dir_hash_changes_per_week",
)

VALID_METRICS: frozenset[str] = frozenset(ALL_METRICS)

# --- rule-id naming ---------------------------------------------------------

RULE_ID_PREFIX: str = "anomaly."


def rule_id_for(metric: str) -> str:
    """Return the canonical rule_id for an anomaly metric.

    >>> rule_id_for("bash_calls_per_day")
    'anomaly.bash_calls_per_day'
    """
    return f"{RULE_ID_PREFIX}{metric}"
