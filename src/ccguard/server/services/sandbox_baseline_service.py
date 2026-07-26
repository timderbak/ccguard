"""Эталон и детект ослабления песочницы (sandbox) Claude Code (ASI03 / T1562).

Песочница — периметр вокруг агента: файловая система, egress (исходящая сеть),
команды вне изоляции. Этот сервис следит НЕ за любым изменением состояния, а
именно за **ослаблением** периметра, потому что асимметрия здесь принципиальна:

  * усиление (включили песочницу, сузили egress-allowlist, добавили запрет
    чтения секретов) — это хорошо; принимаем тихо, двигаем эталон вперёд;
  * ослабление (выключили, расширили allowlist, разрешили команды в обход
    изоляции, сняли fail-closed) — находка ``sandbox.weakened``.

Почему warn, а не block: сервер видит состояние ПОСТ-ФАКТУМ, из sync-отчёта
агента. Блокировать здесь нечего — это видимость и сигнал, а не горячий
PreToolUse-хук. Полное снятие периметра (песочницу выключили целиком) поднимаем
до critical: это качественно иное событие, чем расширить один домен.

Слот — ровно одна строка на машину (состояние песочницы единое, а не список).
Эталон двигается на новое состояние даже при ослаблении — находка уже
зафиксирована в ленте, а повтор того же на следующем sync только шумел бы.

Обратная совместимость: агент v0.1/v0.2 поля ``sandbox`` не шлёт, приходит
``None`` — сервис ничего не трогает и возвращает пустой список.
"""
from __future__ import annotations

import json
from datetime import UTC, datetime

from sqlmodel import Session, select

from ccguard.schemas.inventory import SandboxState
from ccguard.server.db.models import FindingRecord, SandboxBaseline

RULE_ID = "sandbox.weakened"


def _now() -> datetime:
    return datetime.now(UTC).replace(tzinfo=None)


def _lost_true(old: dict, new: dict, key: str) -> bool:
    """Защитный флаг был включён (True) и перестал им быть."""
    return old.get(key) is True and new.get(key) is not True


def _became_true(old: dict, new: dict, key: str) -> bool:
    """Ослабляющий флаг/дыра открылась: не был True, стал True."""
    return old.get(key) is not True and new.get(key) is True


def _added(old: dict, new: dict, key: str) -> list[str]:
    prev = set(old.get(key) or [])
    return [x for x in (new.get(key) or []) if x not in prev]


def _removed(old: dict, new: dict, key: str) -> list[str]:
    cur = set(new.get(key) or [])
    return [x for x in (old.get(key) or []) if x not in cur]


def _perimeter_removed(old: dict, new: dict) -> bool:
    """Периметр снят целиком: песочницу выключили или удалили её конфиг.

    Это качественно иное событие, чем расширить один домен, — поднимаем находку
    до critical.
    """
    return _lost_true(old, new, "enabled") or (
        old.get("configured") is True and new.get("configured") is not True
    )


def detect_weakenings(old: dict, new: dict) -> list[str]:
    """Список человекочитаемых причин, по которым периметр стал СЛАБЕЕ.

    Пусто → ослабления нет (усиление или нейтральное изменение). Каждая строка
    — отдельная ось ослабления; в находку они сворачиваются в один список
    (анти-шум: не находка на ось).
    """
    reasons: list[str] = []

    if old.get("configured") is True and new.get("configured") is not True:
        reasons.append("конфигурация песочницы удалена целиком")
    if _lost_true(old, new, "enabled"):
        reasons.append("песочница выключена (sandbox.enabled=false)")
    if _lost_true(old, new, "fail_if_unavailable"):
        reasons.append(
            "снят fail-closed: если песочница недоступна, Claude Code теперь "
            "тихо работает БЕЗ неё, а не отказывается"
        )
    if _became_true(old, new, "allow_unsandboxed_commands"):
        reasons.append("разрешены команды в обход песочницы (allowUnsandboxedCommands=true)")
    if _became_true(old, new, "weaker_nested_sandbox"):
        reasons.append("включён ослабленный режим вложенной песочницы")
    if _became_true(old, new, "weaker_network_isolation"):
        reasons.append("включена ослабленная сетевая изоляция")
    if _became_true(old, new, "filesystem_disabled"):
        reasons.append("изоляция файловой системы выключена целиком")
    if _lost_true(old, new, "network_allow_managed_domains_only"):
        reasons.append("снято ограничение egress «только домены из managed-конфига»")

    added_domains = _added(old, new, "network_allowed_domains")
    if added_domains:
        reasons.append("egress-allowlist расширен: +" + ", ".join(added_domains))
    removed_denies = _removed(old, new, "network_denied_domains")
    if removed_denies:
        reasons.append("снят запрет egress-доменов: " + ", ".join(removed_denies))
    added_write = _added(old, new, "filesystem_allow_write")
    if added_write:
        reasons.append("расширены пути записи песочницы: +" + ", ".join(added_write))
    removed_denyread = _removed(old, new, "filesystem_deny_read")
    if removed_denyread:
        reasons.append("снята защита чтения — агент снова видит: " + ", ".join(removed_denyread))
    added_excluded = _added(old, new, "excluded_commands")
    if added_excluded:
        reasons.append("больше команд выведено из-под песочницы: +" + ", ".join(added_excluded))

    if new.get("default_mode") == "bypassPermissions" and old.get("default_mode") != "bypassPermissions":
        reasons.append(
            "режим по умолчанию сменён на bypassPermissions — подтверждения "
            "выключены на уровне конфига"
        )

    return reasons


def _make_finding(
    *, machine_id: str, inventory_id: int | None, severity: str,
    reasons: list[str], old: dict, new: dict,
) -> FindingRecord:
    critical = severity == "critical"
    title = (
        "Песочница агента снята" if critical else "Периметр песочницы ослаблен"
    )
    lead = (
        "Периметр вокруг агента снят полностью. "
        if critical else
        "Периметр вокруг агента ослаблен. "
    )
    description = (
        lead
        + "Что изменилось:\n— "
        + "\n— ".join(reasons)
        + "\n\nЕсли это сделал ты осознанно — ничего делать не нужно, эталон уже "
        "обновлён. Если нет — периметр агента кто-то ослабил; проверь, кто и зачем "
        "правил настройки песочницы."
    )
    payload = {
        "rule_id": RULE_ID,
        "severity": severity,
        "title": title,
        "description": description,
        "reasons": reasons,
        "old_state": old,
        "new_state": new,
        "source_scope": new.get("source_scope"),
    }
    return FindingRecord(
        machine_id=machine_id, inventory_id=inventory_id, rule_id=RULE_ID,
        severity=severity, discovered_at=_now(),
        payload_json=json.dumps(payload, ensure_ascii=False),
    )


def update_and_detect(
    session: Session,
    machine_id: str,
    sandbox: SandboxState | None,
    *,
    inventory_id: int | None = None,
) -> list[FindingRecord]:
    """Свести пришедшее состояние песочницы с эталоном. Мутирует сессию.

    Возвращает список находок (0 или 1): одна ``sandbox.weakened`` при
    ослаблении, иначе пусто.
    """
    if sandbox is None:
        return []  # старый агент или песочница не собрана — graceful degradation

    now = _now()
    new_state = sandbox.model_dump()

    existing = session.exec(
        select(SandboxBaseline).where(SandboxBaseline.machine_id == machine_id)
    ).one_or_none()

    # Первый контакт: заводим эталон тихо. Находку «нет песочницы» на bootstrap
    # НЕ делаем — у многих она просто не настроена, и это не «ослабление». Общая
    # поза флота (сколько эндпоинтов без песочницы) видна на UI из configured.
    if existing is None:
        session.add(SandboxBaseline(
            machine_id=machine_id,
            state_json=json.dumps(new_state, ensure_ascii=False),
            configured=sandbox.configured,
            enabled=sandbox.enabled,
            first_seen_at=now, last_seen_at=now, updated_at=now,
        ))
        return []

    existing.last_seen_at = now
    try:
        old_state = json.loads(existing.state_json)
    except (ValueError, TypeError):
        old_state = {}
    if not isinstance(old_state, dict):
        old_state = {}

    findings: list[FindingRecord] = []
    reasons = detect_weakenings(old_state, new_state)
    if reasons:
        severity = "critical" if _perimeter_removed(old_state, new_state) else "warn"
        findings.append(_make_finding(
            machine_id=machine_id, inventory_id=inventory_id, severity=severity,
            reasons=reasons, old=old_state, new=new_state,
        ))

    # Эталон двигаем на новое состояние при ЛЮБОМ изменении (в т.ч. усилении) —
    # так усиление принимается тихо, а ослабление не повторится находкой на
    # следующем sync.
    if old_state != new_state:
        existing.state_json = json.dumps(new_state, ensure_ascii=False)
        existing.configured = sandbox.configured
        existing.enabled = sandbox.enabled
        existing.updated_at = now

    session.add(existing)
    for f in findings:
        session.add(f)
    return findings
