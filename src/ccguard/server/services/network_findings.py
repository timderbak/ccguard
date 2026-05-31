"""Server-side rendering helpers for network.suspicious.* findings (P1).

Зеркало :mod:`ccguard.server.services.dangerous_findings`, но для
network-каталога. Агент шлёт через ``/api/v1/findings`` только title +
matched_pattern (хост/URL); «почему опасно» / «что делать» поднимаем
из дефолтного каталога SuspiciousHostRule по rule_id.
"""
from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta
from typing import Any

from sqlmodel import Session, select

from ccguard.schemas.policy import _default_suspicious_host_rules
from ccguard.server.db.models import FindingRecord

# rule_id → {title, reason, remediation, default_severity}
# В каталоге может быть несколько SuspiciousHostRule с одинаковым id
# (например egress/pastebin для каждого pastebin-хоста). Берём первый —
# title/reason/remediation у них одинаковые, отличается только pattern.
_RULE_META: dict[str, dict[str, str]] = {}
for _r in _default_suspicious_host_rules():
    rid = f"network.suspicious.{_r.id}"
    if rid not in _RULE_META:
        _RULE_META[rid] = {
            "title": _r.title,
            "reason": _r.reason,
            "remediation": _r.remediation,
            "default_severity": _r.severity,
        }


def meta_for(rule_id: str) -> dict[str, str]:
    """Метаданные правила для UI; пустые fallback для unknown rule_id."""
    if rule_id in _RULE_META:
        return _RULE_META[rule_id]
    return {
        "title": rule_id,
        "reason": "",
        "remediation": "",
        "default_severity": "warn",
    }


def _format_card(record: FindingRecord) -> dict[str, Any]:
    try:
        payload = json.loads(record.payload_json) if record.payload_json else {}
    except (ValueError, TypeError):
        payload = {}
    meta = meta_for(record.rule_id)
    title = payload.get("title") or meta.get("title") or record.rule_id
    target = (
        payload.get("matched_value")
        or payload.get("matched_pattern")
        or payload.get("hostname")
        or payload.get("url")
        or ""
    )
    if isinstance(target, str) and len(target) > 200:
        target = target[:200] + "…"
    return {
        "rule_id": record.rule_id,
        "severity": record.severity,
        "machine_id": record.machine_id,
        "discovered_at": record.discovered_at,
        "ts_short": record.discovered_at.strftime("%Y-%m-%d %H:%M"),
        "title": title,
        "reason": meta.get("reason", ""),
        "remediation": meta.get("remediation", ""),
        "target": target,
    }


def recent_network_cards_for_machine(
    session: Session,
    machine_id: str,
    *,
    hours: int = 24,
    limit: int = 30,
) -> list[dict[str, Any]]:
    """Последние подозрительные сетевые вызовы на конкретной машине."""
    cutoff = datetime.now(UTC) - timedelta(hours=hours)
    rows = list(
        session.exec(
            select(FindingRecord)
            .where(FindingRecord.machine_id == machine_id)
            .where(FindingRecord.rule_id.like("network.suspicious.%"))  # type: ignore[attr-defined]
            .where(FindingRecord.discovered_at >= cutoff)
            .order_by(FindingRecord.discovered_at.desc())  # type: ignore[attr-defined]
            .limit(limit)
        )
    )
    return [_format_card(r) for r in rows]
