"""Схемы для hook-протокола enforce."""

from __future__ import annotations

from typing import Any, Literal

from ccguard.schemas._base import SchemaBase


class EnforceHookInput(SchemaBase):
    """То, что Claude Code присылает в stdin хука. Только используемые поля."""

    model_config = {"extra": "ignore"}

    hook_event_name: str
    tool_name: str
    tool_input: dict[str, Any] = {}
    cwd: str | None = None
    session_id: str | None = None


class EnforceDecision(SchemaBase):
    """Внутреннее решение enforce до сериализации в hook-формат."""

    permission: Literal["allow", "deny"]
    reason: str
    rule_id: str | None = None
    fail_open: bool = False
    # Hard deny: a never-legitimate action (reverse shell, disabling ccguard).
    # Blocks REGARDLESS of enforcement_mode — observe does NOT flip it to allow.
    # The "block obvious-evil out of the box" tier.
    hard_deny: bool = False
    # P1 / Dangerous Bash Patterns: rule_id'ы severity=warn правил, которые
    # сматчились, но не блокируют. Сохраняются в audit для последующего
    # анализа без прерывания работы пользователя.
    warning_signals: list[str] = []
