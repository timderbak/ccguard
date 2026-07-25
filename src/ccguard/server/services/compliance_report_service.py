"""Отчёт за период — артефакт, который кладут в папку к аудиту.

Проверяющему (SOC2, ISO 27001, внутренний аудит) не нужен живой дашборд: ему
нужен документ за конкретный период, который можно приложить к делу и который
отвечает на четыре вопроса:

1. **Что вообще под контролем** — сколько машин, сколько из них на связи. Без
   этого остальные цифры не значат ничего: «ноль инцидентов» на нуле машин и
   «ноль инцидентов» на сотне — разные утверждения.
2. **Что средство умеет ловить** — покрытие по признанным каталогам техник
   (MITRE ATT&CK и другие), включая ЧЕСТНЫЕ пробелы. Аудитор ищет не «у нас всё
   зелёное», а понимание собственных границ.
3. **Что произошло** — находки по уровням серьёзности, что было заблокировано.
4. **Кто принимал решения** — журнал согласований: кто и когда одобрил
   индикатор, принял изменение компонента, разложил приманку. Это контрольная
   область «управление изменениями», которую спрашивают по имени.

Отчёт намеренно строится только из уже собранных данных: он ничего не считает
заново и ничего не досчитывает «по-своему», иначе цифры в отчёте разошлись бы с
цифрами на экране — а это первое, за что цепляется проверяющий.
"""
from __future__ import annotations

import logging
from collections import Counter
from datetime import UTC, datetime, timedelta
from typing import Any

from sqlmodel import Session, select

from ccguard.server.db.models import (
    CanaryToken,
    FindingRecord,
    Machine,
    MCPServerBaseline,
    ProtectionIncident,
    ThreatIndicator,
)

log = logging.getLogger(__name__)

DEFAULT_PERIOD_DAYS = 30
# Сколько записей журнала решений показывать. Отчёт — документ, а не выгрузка:
# полный список берут через экспорт, здесь нужна представительная выборка.
_DECISION_LIMIT = 50


def _period_bounds(days: int, *, now: datetime | None = None) -> tuple[datetime, datetime]:
    end = now or datetime.now(UTC)
    return end - timedelta(days=days), end


def _fleet(session: Session, since: datetime) -> dict[str, Any]:
    machines = list(session.exec(select(Machine)))
    # «На связи» считаем по последнему контакту внутри периода: машина, молчащая
    # месяц, не должна попадать в отчёт как наблюдаемая.
    since_naive = since.replace(tzinfo=None)
    active = [m for m in machines if m.last_seen and m.last_seen >= since_naive]
    return {
        "total": len(machines),
        "active": len(active),
        "silent": len(machines) - len(active),
    }


def _findings(session: Session, since: datetime) -> dict[str, Any]:
    rows = list(
        session.exec(select(FindingRecord).where(FindingRecord.discovered_at >= since))
    )
    by_sev = Counter(r.severity for r in rows)
    by_rule = Counter(r.rule_id for r in rows)
    return {
        "total": len(rows),
        "by_severity": {
            k: by_sev.get(k, 0) for k in ("critical", "block", "warn", "info")
        },
        "top_rules": by_rule.most_common(10),
        # Корреляции (ioa.*) выделяем отдельно: это связанные цепочки, а не
        # разрозненные события, и именно они показывают ценность средства.
        "correlations": sum(1 for r in rows if r.rule_id.startswith("ioa.")),
    }


def _coverage(session: Session) -> dict[str, Any]:
    """Покрытие по каталогам техник — вместе с честными пробелами."""
    try:
        from ccguard.server.services import coverage_service

        covered = coverage_service.techniques_covered(session)
        uncovered = coverage_service.techniques_uncovered(session)
        by_tactic = coverage_service.coverage_by_tactic(session)
    except Exception as exc:  # noqa: BLE001 — отчёт не должен падать целиком
        log.warning("отчёт: не удалось собрать покрытие: %s", exc)
        return {"covered": 0, "uncovered": 0, "by_tactic": {}, "gaps": []}
    return {
        "covered": len(covered),
        "uncovered": len(uncovered),
        "by_tactic": by_tactic,
        # Пробелы показываем явно и списком: аудитор ищет не «всё зелёное»,
        # а понимание собственных границ.
        "gaps": [
            {"id": t.technique_id, "name": t.name, "tactic": t.tactic}
            for t in uncovered[:15]
        ],
    }


def _decisions(session: Session, since: datetime) -> list[dict[str, Any]]:
    """Журнал решений: кто и что согласовал за период.

    Это контрольная область «управление изменениями» — её спрашивают по имени
    (SOC2 CC8, ISO 27001 A.8.32). Собирается из уже существующих отметок
    «кто принял» на разных сущностях, отдельного журнала для этого не заводится.
    """
    out: list[dict[str, Any]] = []
    since_naive = since.replace(tzinfo=None)

    def _within(dt: datetime | None) -> bool:
        if dt is None:
            return False
        return (dt.replace(tzinfo=None) if dt.tzinfo else dt) >= since_naive

    try:
        for ind in session.exec(
            select(ThreatIndicator).where(ThreatIndicator.reviewed_by.is_not(None))  # type: ignore[attr-defined]
        ):
            if _within(ind.reviewed_at):
                out.append({
                    "at": ind.reviewed_at,
                    "who": ind.reviewed_by,
                    "what": "индикатор",
                    "object": f"{ind.indicator_type}: {ind.value[:60]}",
                    "decision": "одобрен" if ind.status == "active" else ind.status,
                })
        for mcp in session.exec(
            select(MCPServerBaseline).where(MCPServerBaseline.accepted_by.is_not(None))  # type: ignore[attr-defined]
        ):
            if _within(mcp.accepted_at):
                out.append({
                    "at": mcp.accepted_at,
                    "who": mcp.accepted_by,
                    "what": "MCP-сервер",
                    "object": f"{mcp.mcp_name} на {mcp.machine_id}",
                    "decision": "проверен",
                })
        for can in session.exec(select(CanaryToken)):
            if _within(can.created_at):
                out.append({
                    "at": can.created_at,
                    "who": can.created_by,
                    "what": "приманка",
                    "object": can.file_path,
                    "decision": "создана",
                })
        # Разбор машин, оставшихся без защиты. Отклонённые объяснения попадают
        # сюда наравне с принятыми: отчёт, где видны только принятые решения,
        # ничего не говорит о том, работает ли процесс.
        for inc in session.exec(
            select(ProtectionIncident).where(
                ProtectionIncident.reviewed_by.is_not(None)  # type: ignore[attr-defined]
            )
        ):
            if _within(inc.reviewed_at):
                out.append({
                    "at": inc.reviewed_at,
                    "who": inc.reviewed_by,
                    "what": "машина без защиты",
                    "object": f"{inc.machine_id} ({inc.state}): {(inc.explanation or '—')[:60]}",
                    "decision": "принято" if inc.status == "accepted" else "отклонено",
                })
    except Exception as exc:  # noqa: BLE001 — отчёт не должен падать целиком
        log.warning("отчёт: не удалось собрать журнал решений: %s", exc)

    out.sort(key=lambda d: (d["at"] is None, d["at"]), reverse=True)
    return out[:_DECISION_LIMIT]


def _canaries(session: Session) -> dict[str, Any]:
    rows = list(session.exec(select(CanaryToken)))
    return {
        "total": len(rows),
        "armed": sum(1 for c in rows if c.status == "armed"),
        "triggered": sum(1 for c in rows if c.status == "triggered"),
    }


def _protection(session: Session) -> dict[str, Any]:
    """Машины, оставшиеся без защиты, и что с этим сделали.

    Отдельным разделом, а не строкой в охвате: проверяющего интересует не
    столько сам факт, сколько наличие процесса — спросили ли причину, кто
    принял решение, сколько вопросов остались без ответа. Незакрытые считаются
    честно и показываются: скрывать их значит показывать не то, как есть.
    """
    try:
        from ccguard.server.services import protection_incident_service as pis

        return pis.summary(session)
    except Exception as exc:  # noqa: BLE001 — отчёт не должен падать целиком
        log.warning("отчёт: разбор машин без защиты недоступен: %s", exc)
        return {}


def _blocks(session: Session, since: datetime) -> dict[str, Any]:
    """Заблокированные действия за период — и отдельно случаи «пропустили».

    ``fail_open`` показывается наравне с блокировками намеренно: это моменты,
    когда защита НЕ смогла принять решение и пропустила действие. Отчёт, который
    показывает только успехи, аудитор справедливо считает недостоверным.
    """
    try:
        from ccguard.server.db.models import AuditRecord

        rows = list(
            session.exec(select(AuditRecord).where(AuditRecord.received_at >= since))
        )
        denied = [r for r in rows if r.decision == "deny"]
        fail_open = [r for r in rows if r.fail_open]
        by_rule = Counter(r.rule_id or "—" for r in denied)
        return {
            "total": len(denied),
            "fail_open": len(fail_open),
            "top_rules": by_rule.most_common(10),
        }
    except Exception as exc:  # noqa: BLE001 — отчёт не должен падать целиком
        log.warning("отчёт: блокировки недоступны: %s", exc)
        return {"total": 0, "fail_open": 0, "top_rules": []}


def build_report(
    session: Session, *, days: int = DEFAULT_PERIOD_DAYS, now: datetime | None = None
) -> dict[str, Any]:
    """Собрать отчёт за период из уже накопленных данных."""
    since, end = _period_bounds(days, now=now)
    return {
        "period_days": days,
        "period_start": since,
        "period_end": end,
        "generated_at": datetime.now(UTC),
        "fleet": _fleet(session, since),
        "findings": _findings(session, since),
        "coverage": _coverage(session),
        "canaries": _canaries(session),
        "protection": _protection(session),
        "blocks": _blocks(session, since),
        "decisions": _decisions(session, since),
    }
