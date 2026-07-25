"""Выгрузка находок: CSV для человека, JSON для машины.

Зачем это нужно отдельным механизмом. Инструмент безопасности, из которого
данные можно только разглядывать в браузере, в корпоративной среде считается
игрушкой: у команды уже есть SIEM (система сбора и анализа событий безопасности,
куда стекаются данные со всех защитных средств), и любое новое средство обязано
уметь в неё отдавать. Отдельно от SIEM существует аудит — там нужен файл,
который человек откроет в таблице и приложит к отчёту.

Отсюда два формата, а не один:

* **CSV** — для человека и для аудита. Открывается в Excel, читается глазами,
  колонки плоские. Вложенные подробности находки сворачиваются в текст, потому
  что таблица не умеет вложенность.
* **JSON** — для машины. Подробности находки остаются структурой, ничего не
  теряется при разборе на приёмной стороне.

Фильтры намеренно те же, что на странице находок: оператор отбирает глазами то,
что ему нужно, и выгружает ровно это — без второго, отдельно устроенного набора
параметров, который неизбежно разъехался бы с первым.
"""
from __future__ import annotations

import csv
import io
import json
from datetime import UTC, datetime, timedelta
from typing import Any

from sqlmodel import Session, select

from ccguard.server.db.models import FindingRecord

# Колонки CSV. Порядок зафиксирован: файл выгрузки попадает в чужие таблицы и
# скрипты, поэтому перестановка колонок ломала бы их так же, как смена формата.
CSV_COLUMNS: tuple[str, ...] = (
    "discovered_at",
    "machine_id",
    "rule_id",
    "severity",
    "title",
    "description",
    "recommendation",
    "matched_value",
    "source",
)


def select_findings(
    session: Session,
    *,
    severity: str | None = None,
    rule_id: str | None = None,
    machine_id: str | None = None,
    since_days: int | None = None,
    limit: int = 10000,
) -> list[FindingRecord]:
    """Находки по тем же фильтрам, что и на странице.

    Верхняя граница ``limit`` существует не ради красоты: выгрузка формируется в
    памяти, и без предела одна кнопка могла бы положить сервер на большой базе.
    """
    stmt = select(FindingRecord)
    if severity:
        stmt = stmt.where(FindingRecord.severity == severity)
    if rule_id:
        stmt = stmt.where(FindingRecord.rule_id == rule_id)
    if machine_id:
        stmt = stmt.where(FindingRecord.machine_id == machine_id)
    if since_days:
        stmt = stmt.where(FindingRecord.discovered_at >= datetime.now(UTC) - timedelta(days=since_days))
    stmt = stmt.order_by(FindingRecord.discovered_at.desc()).limit(limit)  # type: ignore[attr-defined]
    return list(session.exec(stmt))


def _payload(row: FindingRecord) -> dict[str, Any]:
    try:
        data = json.loads(row.payload_json or "{}")
    except (ValueError, TypeError):
        return {}
    return data if isinstance(data, dict) else {}


def _flatten(value: Any) -> str:
    """Свернуть значение в одну ячейку таблицы.

    В подробностях находки встречаются списки и словари (например перечень
    сигналов). CSV вложенности не знает, поэтому такие значения записываются
    компактным JSON — читаемо глазами и разбираемо скриптом, если понадобится.
    """
    if value is None:
        return ""
    if isinstance(value, str):
        return value
    if isinstance(value, (int, float, bool)):
        return str(value)
    return json.dumps(value, ensure_ascii=False, separators=(",", ":"))


def to_csv(rows: list[FindingRecord]) -> str:
    """CSV с заголовком. Всегда возвращает шапку — даже на пустой выборке,
    иначе принимающая сторона не отличит «ничего не найдено» от «файл битый»."""
    buf = io.StringIO()
    writer = csv.writer(buf, lineterminator="\n")
    writer.writerow(CSV_COLUMNS)
    for r in rows:
        p = _payload(r)
        writer.writerow([
            r.discovered_at.isoformat(),
            r.machine_id,
            r.rule_id,
            r.severity,
            _flatten(p.get("title")),
            _flatten(p.get("description") or p.get("narrative")),
            _flatten(p.get("recommendation")),
            _flatten(p.get("matched_value")),
            _flatten(p.get("source")),
        ])
    return buf.getvalue()


def to_json(rows: list[FindingRecord]) -> str:
    """JSON для машинной обработки: подробности остаются структурой.

    Обёртка с ``exported_at`` и ``count`` нужна принимающей стороне, чтобы
    отличить пустую выгрузку от неудавшейся и понять, на какой момент данные.
    """
    payload = {
        "exported_at": datetime.now(UTC).isoformat(),
        "count": len(rows),
        "findings": [
            {
                "id": r.id,
                "discovered_at": r.discovered_at.isoformat(),
                "machine_id": r.machine_id,
                "rule_id": r.rule_id,
                "severity": r.severity,
                "details": _payload(r),
            }
            for r in rows
        ],
    }
    return json.dumps(payload, ensure_ascii=False, indent=2)


def filename(fmt: str, *, now: datetime | None = None) -> str:
    """Имя файла с датой — чтобы выгрузки не перезаписывали друг друга в папке
    «Загрузки» и было видно, за какой момент данные."""
    stamp = (now or datetime.now(UTC)).strftime("%Y%m%d-%H%M")
    ext = "csv" if fmt == "csv" else "json"
    return f"ccguard-findings-{stamp}.{ext}"
