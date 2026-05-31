"""Server-side rendering helpers for dangerous.* findings (P1).

Агент шлёт через `/api/v1/findings` только ``title`` и ``matched_pattern``
(сам command snippet). «Почему опасно» / «что делать» теряются по дороге
(чтобы не плодить мусор в wire-schema). Здесь — серверный реестр reason +
remediation по rule_id, который совпадает с дефолтным набором
``DangerousBashRule`` в :mod:`ccguard.schemas.policy`.

Если пользователь добавил custom dangerous rule — мы покажем title +
command snippet без reason/remediation (graceful degradation), пока UI
для подгрузки custom-метаданных не появится в v0.3.
"""
from __future__ import annotations

from datetime import UTC, datetime
from typing import Any, Iterable

from sqlmodel import Session, select

from ccguard.schemas.policy import _default_dangerous_patterns
from ccguard.server.db.models import FindingRecord

_RULE_META: dict[str, dict[str, str]] = {
    f"dangerous.{r.id}": {
        "title": r.title,
        "reason": r.reason,
        "remediation": r.remediation,
        "category": r.category,
        "default_severity": r.severity,
    }
    for r in _default_dangerous_patterns()
}


def meta_for(rule_id: str) -> dict[str, str]:
    """Возвращает {title, reason, remediation, category} для rule_id.

    Для custom-правил, которых нет в дефолтном каталоге, отдаёт пустые
    строки в reason/remediation и rule_id как fallback title.
    """
    if rule_id in _RULE_META:
        return _RULE_META[rule_id]
    return {
        "title": rule_id,
        "reason": "",
        "remediation": "",
        "category": "",
        "default_severity": "block",
    }


def _format_card(record: FindingRecord) -> dict[str, Any]:
    import json
    try:
        payload = json.loads(record.payload_json) if record.payload_json else {}
    except (ValueError, TypeError):
        payload = {}
    meta = meta_for(record.rule_id)
    # Title из payload приоритетнее (агент мог его обновить), fallback на meta.
    title = payload.get("title") or meta.get("title") or record.rule_id
    cmd_snippet = (
        payload.get("matched_value")
        or payload.get("matched_pattern")
        or payload.get("description")
        or ""
    )
    if isinstance(cmd_snippet, str) and len(cmd_snippet) > 200:
        cmd_snippet = cmd_snippet[:200] + "…"
    return {
        "rule_id": record.rule_id,
        "severity": record.severity,
        "machine_id": record.machine_id,
        "ts_short": record.discovered_at.strftime("%Y-%m-%d %H:%M"),
        "title": title,
        "reason": meta.get("reason", ""),
        "remediation": meta.get("remediation", ""),
        "command_snippet": cmd_snippet,
    }


def recent_dangerous_cards(session: Session, *, limit: int = 10) -> list[dict[str, Any]]:
    """Последние N findings c rule_id LIKE 'dangerous.%' для overview-ленты."""
    rows = list(
        session.exec(
            select(FindingRecord)
            .where(FindingRecord.rule_id.like("dangerous.%"))  # type: ignore[attr-defined]
            .order_by(FindingRecord.discovered_at.desc())  # type: ignore[attr-defined]
            .limit(limit)
        )
    )
    return [_format_card(r) for r in rows]


def todays_blocked_count(session: Session) -> int:
    """Счётчик block-severity dangerous findings за сегодня (UTC).

    Используется на overview для бэйджа «за сегодня заблокировано N» в
    enforce-режиме / «было бы заблокировано N» в observe.
    """
    from sqlalchemy import func as _func

    start = datetime.now(UTC).replace(hour=0, minute=0, second=0, microsecond=0)
    n = session.exec(
        select(_func.count())  # type: ignore[arg-type]
        .select_from(FindingRecord)
        .where(FindingRecord.rule_id.like("dangerous.%"))  # type: ignore[attr-defined]
        .where(FindingRecord.severity == "block")
        .where(FindingRecord.discovered_at >= start)
    ).one()
    # session.exec returns scalar for func.count
    if isinstance(n, tuple):
        n = n[0]
    return int(n or 0)


def cards_from_records(records: Iterable[FindingRecord]) -> list[dict[str, Any]]:
    """Public helper for tests / other callers."""
    return [_format_card(r) for r in records]
