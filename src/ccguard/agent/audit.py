"""Audit-лог: JSON-lines с ротацией. Используется из enforce."""

from __future__ import annotations

import json
import logging
from logging.handlers import RotatingFileHandler
from pathlib import Path

# Импорт напрямую из hot_types, НЕ через ccguard.schemas: audit на горячем
# пути (write_audit зовётся из enforce), а пакет schemas тянет pydantic.
from ccguard.agent.hot_types import (
    AuditEntry,
    audit_entry_from_dict,
    audit_entry_to_dict,
)


def make_audit_logger(audit_path: Path, max_bytes: int, backup_count: int) -> logging.Logger:
    """Создать stand-alone logger, пишущий JSON-lines с ротацией."""
    audit_path.parent.mkdir(parents=True, exist_ok=True)
    logger = logging.getLogger(f"ccguard.audit.{audit_path}")
    logger.setLevel(logging.INFO)
    logger.propagate = False
    if not logger.handlers:
        handler = RotatingFileHandler(
            audit_path,
            maxBytes=max_bytes,
            backupCount=backup_count,
            encoding="utf-8",
        )
        handler.setFormatter(logging.Formatter("%(message)s"))
        logger.addHandler(handler)
    return logger


def write_audit(logger: logging.Logger, entry: AuditEntry) -> None:
    logger.info(json.dumps(audit_entry_to_dict(entry), ensure_ascii=False))


def read_audit_entries(audit_path: Path) -> list[AuditEntry]:
    """Прочитать все записи (для sync). Игнорирует битые строки."""
    if not audit_path.exists():
        return []
    out: list[AuditEntry] = []
    for line in audit_path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            data = json.loads(line)
            out.append(audit_entry_from_dict(data))
        except (json.JSONDecodeError, ValueError, KeyError):
            continue
    return out
