"""Детект отравления АВТО-памяти Claude Code по аномальной дельте (ASI06).

Авто-память агент переписывает сам каждую сессию, поэтому дрейф отпечатка (как у
CLAUDE.md) тут бесполезен — он срабатывал бы всегда. Вместо этого сравниваем
числовые признаки текущего снимка с ПРЕДЫДУЩИМ снимком того же файла и ловим
резкую дельту:

  * внезапный вброс объёма (скачок строк/байт) — automemory.anomaly;
  * появление НОВОГО внешнего @import (авто-память тянет файл извне);
  * всплеск атака-маркеров (ignore previous / curl|base64 / secret-паттерны) или
    URL — вброс инструкции/адреса эксфильтрации.

Почему сравнение с предыдущим снимком, а не с древним эталоном: авто-память
легитимно растёт постепенно (агент дописывает выученное). Дельта к соседнему
sync'у у постепенного роста мала — тихо; у внезапного вброса велика — сигнал.
Так мы не приучаем оператора игнорировать находки на нормальном росте.

Первый контакт (bootstrap) тихий. Эталон двигается на новый снимок при любом
изменении — находка уже в ленте, повтор того же не спамит. Содержимое не
хранится (конституция) — только счётчики; всё уже посчитано на стороне агента.

Пороги — осознанно консервативные и вынесены в константы: ложная тревога на
рядовой правке памяти дороже редкого пропуска, потому что зашумлённый детектор
оператор отключает целиком.
"""
from __future__ import annotations

import json
from datetime import UTC, datetime

from sqlmodel import Session, select

from ccguard.schemas.inventory import AutoMemoryStats
from ccguard.server.db.models import AutoMemoryBaseline, FindingRecord

RULE_ID = "automemory.anomaly"

# Пороги дельты (к предыдущему снимку). Абсолютные — робастны к размеру базы:
# индекс авто-памяти по замыслу держится компактным (Claude выносит детали в
# тематические файлы), поэтому скачок в один sync аномален независимо от базы.
_GROWTH_LINES = 50
_GROWTH_BYTES = 6000
# Скачок атака-маркеров/URL. Одиночное легитимное упоминание («тестируй через
# curl») не должно срабатывать — ловим именно прыжок.
_MARKER_JUMP = 3
_URL_JUMP = 4


def _now() -> datetime:
    return datetime.now(UTC).replace(tzinfo=None)


def detect_anomalies(
    old: AutoMemoryBaseline, new: AutoMemoryStats
) -> tuple[list[str], str]:
    """Причины аномалии и severity по дельте (old-снимок → new-снимок).

    Пусто → аномалии нет. severity: critical, когда появился новый внешний
    @import И одновременно скочок атака-маркеров (сочетание — почти наверняка
    закладка); иначе warn.
    """
    reasons: list[str] = []

    d_lines = new.line_count - old.line_count
    d_bytes = new.size_bytes - old.size_bytes
    if d_lines >= _GROWTH_LINES or d_bytes >= _GROWTH_BYTES:
        reasons.append(
            f"резкий рост объёма за один sync: +{d_lines} строк / +{d_bytes} байт "
            "(вброс большого блока в память)"
        )

    new_external = new.external_import_count > old.external_import_count
    if new_external:
        reasons.append(
            "появился новый внешний @import — авто-память тянет файл извне проекта "
            "(инструкция, которой нет в том, что ревьюят)"
        )

    d_markers = new.suspicious_marker_count - old.suspicious_marker_count
    marker_jump = d_markers >= _MARKER_JUMP
    if marker_jump:
        reasons.append(
            f"всплеск атака-маркеров: +{d_markers} (ignore previous / curl|base64 / "
            "secret-паттерны — типичны для закладки в память)"
        )

    d_urls = new.url_count - old.url_count
    if d_urls >= _URL_JUMP:
        reasons.append(
            f"всплеск URL: +{d_urls} (возможен вброшенный адрес эксфильтрации)"
        )

    if not reasons:
        return [], "warn"

    severity = "critical" if (new_external and marker_jump) else "warn"
    return reasons, severity


def _make_finding(
    *, machine_id: str, inventory_id: int | None, severity: str,
    path: str, reasons: list[str], old: AutoMemoryBaseline, new: AutoMemoryStats,
) -> FindingRecord:
    title = (
        "Похоже на отравление авто-памяти агента"
        if severity == "critical" else
        "Аномалия в авто-памяти агента"
    )
    description = (
        f"Авто-память {path} изменилась подозрительно между сессиями. "
        "Авто-память — прямые инструкции, которые агент даёт сам себе и грузит в "
        "каждую сессию; закладка здесь исполнится с его полномочиями.\n\nЧто "
        "насторожило:\n— " + "\n— ".join(reasons)
        + "\n\nПосмотри содержимое файла. Если рост/правку сделал агент по делу — "
        "эталон уже обновлён, повтора не будет; если нет — это персистентная "
        "закладка в память."
    )
    payload = {
        "rule_id": RULE_ID, "severity": severity, "title": title,
        "description": description, "reasons": reasons, "path": path,
        "old": {
            "size_bytes": old.size_bytes, "line_count": old.line_count,
            "external_import_count": old.external_import_count,
            "url_count": old.url_count,
            "suspicious_marker_count": old.suspicious_marker_count,
        },
        "new": {
            "size_bytes": new.size_bytes, "line_count": new.line_count,
            "external_import_count": new.external_import_count,
            "url_count": new.url_count,
            "suspicious_marker_count": new.suspicious_marker_count,
        },
    }
    return FindingRecord(
        machine_id=machine_id, inventory_id=inventory_id, rule_id=RULE_ID,
        severity=severity, discovered_at=_now(),
        payload_json=json.dumps(payload, ensure_ascii=False),
    )


def _apply(row: AutoMemoryBaseline, new: AutoMemoryStats, now: datetime) -> bool:
    """Перенести новый снимок в строку эталона. True — если что-то менялось."""
    changed = (
        row.content_hash != new.content_hash
        or row.size_bytes != new.size_bytes
        or row.line_count != new.line_count
        or row.external_import_count != new.external_import_count
        or row.url_count != new.url_count
        or row.suspicious_marker_count != new.suspicious_marker_count
        or row.import_count != new.import_count
    )
    row.size_bytes = new.size_bytes
    row.line_count = new.line_count
    row.import_count = new.import_count
    row.external_import_count = new.external_import_count
    row.url_count = new.url_count
    row.suspicious_marker_count = new.suspicious_marker_count
    row.content_hash = new.content_hash
    row.last_seen_at = now
    if changed:
        row.updated_at = now
    return changed


def update_and_detect(
    session: Session,
    machine_id: str,
    current: list[AutoMemoryStats],
    *,
    inventory_id: int | None = None,
) -> list[FindingRecord]:
    """Свести признаки авто-памяти с предыдущим снимком. Мутирует сессию.

    Пустой список → no-op: агент v0.1/v0.2 поле не шлёт, и это неотличимо от
    «авто-память выключена». Не реконсилим исчезновения (удаление авто-памяти —
    слабый сигнал атаки; закладку кладут, а не стирают).
    """
    if not current:
        return []

    now = _now()
    findings: list[FindingRecord] = []

    for stat in current:
        existing = session.exec(
            select(AutoMemoryBaseline).where(
                AutoMemoryBaseline.machine_id == machine_id,
                AutoMemoryBaseline.path == stat.path,
            )
        ).one_or_none()

        if existing is None:
            # Первый контакт с этим файлом — тихо фиксируем снимок.
            session.add(AutoMemoryBaseline(
                machine_id=machine_id, path=stat.path,
                size_bytes=stat.size_bytes, line_count=stat.line_count,
                import_count=stat.import_count,
                external_import_count=stat.external_import_count,
                url_count=stat.url_count,
                suspicious_marker_count=stat.suspicious_marker_count,
                content_hash=stat.content_hash,
                first_seen_at=now, last_seen_at=now, updated_at=now,
            ))
            continue

        reasons, severity = detect_anomalies(existing, stat)
        if reasons:
            findings.append(_make_finding(
                machine_id=machine_id, inventory_id=inventory_id, severity=severity,
                path=stat.path, reasons=reasons, old=existing, new=stat,
            ))
        _apply(existing, stat, now)
        session.add(existing)

    for f in findings:
        session.add(f)
    return findings
