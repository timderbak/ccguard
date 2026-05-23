"""Finding — результат применения policy к inventory."""

from __future__ import annotations

from typing import Literal

from ccguard.schemas._base import SchemaBase

Severity = Literal["info", "warn", "block"]


class Finding(SchemaBase):
    rule_id: str
    severity: Severity
    title: str
    description: str
    source: str
    recommendation: str
    matched_value: str | None = None
