"""Лёгкие типы горячего пути enforce — без pydantic.

Проверка встроена в каждый вызов инструмента, и всё, что она тратит на старте,
разработчик ждёт лично. Импорт pydantic на этом пути стоит ~90мс, а построение
его моделей — ещё ~110мс: вместе это вдвое превышает весь бюджет проверки
(100мс) ещё до того, как та началась. Поэтому вход хука и решение enforce здесь
представлены обычными dataclass'ами, а не pydantic-моделями.

Валидацию это не отменяет: pydantic по-прежнему проверяет политику на сервере и
при синхронизации (где бюджета нет). Горячий путь лишь ЧИТАЕТ уже проверенное,
а не валидирует заново на каждом вызове.

API намеренно совпадает с прежними pydantic-моделями (те же имена полей и
конструирование по ключевым словам), чтобы код enforce и тесты не переписывать.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from typing import Any


@dataclass
class EnforceHookInput:
    """То, что Claude Code присылает в stdin хука. Только используемые поля."""

    hook_event_name: str
    tool_name: str
    tool_input: dict[str, Any] = field(default_factory=dict)
    cwd: str | None = None
    session_id: str | None = None


@dataclass
class EnforceDecision:
    """Внутреннее решение enforce до сериализации в hook-формат."""

    permission: str  # "allow" | "deny"
    reason: str
    rule_id: str | None = None
    fail_open: bool = False
    # Hard deny: заведомо нелегитимное действие (reverse shell, отключение
    # ccguard). Блокирует НЕЗАВИСИМО от enforcement_mode — observe не превращает
    # его в allow. Ярус «резать очевидное зло из коробки».
    hard_deny: bool = False
    # rule_id'ы severity=warn правил, которые сматчились, но не блокируют —
    # сохраняются в audit для анализа, не прерывая работу.
    warning_signals: list[str] = field(default_factory=list)


@dataclass
class AuditEntry:
    """Запись аудита одного решения enforce (пишется в локальный лог)."""

    timestamp: datetime
    tool_name: str
    decision: str  # "allow" | "deny"
    tool_input_fingerprint: str
    rule_id: str | None = None
    reason: str | None = None
    fail_open: bool = False


def audit_entry_to_dict(entry: AuditEntry) -> dict[str, Any]:
    """Сериализовать запись аудита в JSON-совместимый dict.

    Повторяет прежний ``AuditEntry.model_dump(mode="json")``: datetime → ISO.
    """
    return {
        "timestamp": entry.timestamp.isoformat(),
        "tool_name": entry.tool_name,
        "decision": entry.decision,
        "rule_id": entry.rule_id,
        "reason": entry.reason,
        "fail_open": entry.fail_open,
        "tool_input_fingerprint": entry.tool_input_fingerprint,
    }


def audit_entry_from_dict(data: dict[str, Any]) -> AuditEntry:
    """Разобрать запись аудита из dict (замена ``AuditEntry.model_validate``)."""
    ts = data["timestamp"]
    if isinstance(ts, str):
        ts = datetime.fromisoformat(ts)
    return AuditEntry(
        timestamp=ts,
        tool_name=data["tool_name"],
        decision=data["decision"],
        tool_input_fingerprint=data["tool_input_fingerprint"],
        rule_id=data.get("rule_id"),
        reason=data.get("reason"),
        fail_open=bool(data.get("fail_open", False)),
    )


def parse_hook_input(data: dict[str, Any]) -> EnforceHookInput:
    """Разобрать payload хука из уже распарсенного JSON.

    Заменяет ``EnforceHookInput.model_validate``: лишние поля игнорируются
    (как ``extra="ignore"`` в прежней модели), tool_input по умолчанию пустой
    словарь. Отсутствие обязательных полей — это битый payload; поднимаем
    ``KeyError``/``TypeError``, которые горячий путь ловит как fail-open, ровно
    как раньше ловил ошибку валидации pydantic.
    """
    if not isinstance(data, dict):
        raise TypeError("hook payload must be a JSON object")
    tool_input = data.get("tool_input") or {}
    if not isinstance(tool_input, dict):
        tool_input = {}
    return EnforceHookInput(
        hook_event_name=str(data.get("hook_event_name", "")),
        tool_name=str(data["tool_name"]),
        tool_input=tool_input,
        cwd=data.get("cwd"),
        session_id=data.get("session_id"),
    )
