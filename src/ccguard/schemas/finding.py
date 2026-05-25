"""Finding — результат применения policy к inventory."""

from __future__ import annotations

from typing import Literal

from ccguard.schemas._base import SchemaBase

# Order matters for stable serialization across phases. ``critical`` was
# added in Phase 3 / Plan 03-01 for the LLM content scanner (locked decision
# D-01 in 03-CONTEXT.md): additive only — Phase 1+2 emit sites that produce
# {info, warn, block} continue to validate unchanged.
Severity = Literal["info", "warn", "block", "critical"]


class Finding(SchemaBase):
    rule_id: str
    severity: Severity
    title: str
    description: str
    source: str
    recommendation: str
    matched_value: str | None = None
