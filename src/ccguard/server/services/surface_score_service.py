"""MCP-surface score (UI redesign Фаза 1) — read-only.

Стартовая метрика 0–100 «насколько безопасна MCP/agent-поверхность», завязанная
на число уникальных MCP-серверов и наличие открытых block/critical-находок. Это
ВЫВЕСКА над уже посчитанными данными — никаких движков детекта не трогает.

Формула — стартовая, помечена под калибровку на реальных данных (см. спеку §7):
    score = 100 − 8·(машины с block/critical за 7д) − 2·max(0, #MCP − 5)
clamp 0..100. Пустая БД → 100.
"""
from __future__ import annotations

from datetime import UTC, datetime, timedelta

from sqlmodel import Session, select

from ccguard.server.db.models import FindingRecord, Machine
from ccguard.server.services.machine_service import get_latest_inventory_json

_RISK_SEVERITIES = ("block", "critical")
_WINDOW_DAYS = 7
_SAFE_MCP_FLOOR = 5  # surface больше этого начинает слегка снижать оценку


def _unique_mcp_count(session: Session) -> int:
    names: set[str] = set()
    for mid in session.exec(select(Machine.machine_id)).all():
        inv = get_latest_inventory_json(session, mid)
        if not isinstance(inv, dict):
            continue
        servers = inv.get("mcp_servers")
        if not isinstance(servers, list):
            continue
        for s in servers:
            name = s.get("name") if isinstance(s, dict) else None
            if isinstance(name, str) and name:
                names.add(name)
    return len(names)


def compute_surface_score(session: Session) -> dict:
    """Return {score, mcp_count, risk_count}. Read-only, never raises on empty DB."""
    mcp_count = _unique_mcp_count(session)
    since = datetime.now(UTC) - timedelta(days=_WINDOW_DAYS)
    risk_machines = {
        row
        for row in session.exec(
            select(FindingRecord.machine_id)
            .where(FindingRecord.severity.in_(_RISK_SEVERITIES))
            .where(FindingRecord.discovered_at >= since)
        ).all()
    }
    risk_count = len(risk_machines)
    score = 100 - 8 * risk_count - 2 * max(0, mcp_count - _SAFE_MCP_FLOOR)
    score = max(0, min(100, score))
    return {"score": score, "mcp_count": mcp_count, "risk_count": risk_count}
