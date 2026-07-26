"""Пути и лёгкое чтение конфига агента для горячего пути — без pydantic.

``config.py`` определяет конфиг агента pydantic-моделями, и сам факт импорта
этого модуля строит их (~200мс) — недопустимо на пути проверки, встроенной в
каждый вызов инструмента. Здесь лежат:

* функции путей (``default_config_dir`` и т.п.) — чистый ``os.path``, их
  ``config.py`` реэкспортирует ради обратной совместимости;
* ``FastConfig`` + ``load_fast_config`` — читают config.yaml только для тех
  полей, что нужны enforce, обычным ``yaml.safe_load`` без валидации.

Дефолты продублированы из ``config.py`` СОЗНАТЕЛЬНО и защищены тестом
эквивалентности (``test_fast_config_equivalence``): их всего четыре, они
скалярные, и расхождение падает тестом. Для config это безопасно — в отличие
от политики, здесь нет защитных списков, потеря которых открыла бы дыру.
"""
from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path

import yaml

# Дефолты — зеркало config.py (AuditSection / PolicySection). Их сверяет
# test_fast_config_equivalence.
_DEFAULT_AUDIT_MAX_BYTES = 10 * 1024 * 1024
_DEFAULT_AUDIT_BACKUP_COUNT = 5
_DEFAULT_CACHE_PATH = "~/.ccguard/policy.yaml"


def default_config_dir() -> Path:
    """~/.ccguard. Переопределяется через CCGUARD_AGENT_HOME (для тестов)."""
    override = os.environ.get("CCGUARD_AGENT_HOME")
    if override:
        return Path(override)
    return Path(os.path.expanduser("~/.ccguard"))


def default_config_path() -> Path:
    return default_config_dir() / "config.yaml"


@dataclass
class _AuditView:
    max_bytes: int = _DEFAULT_AUDIT_MAX_BYTES
    backup_count: int = _DEFAULT_AUDIT_BACKUP_COUNT


@dataclass
class _PolicyView:
    cache_path: str = _DEFAULT_CACHE_PATH
    block_fail_mode: str | None = None  # None = взять из самой policy


@dataclass
class FastConfig:
    """Только те поля конфига, что читает горячий путь enforce."""

    audit: _AuditView
    policy: _PolicyView

    def resolved_cache_path(self) -> Path:
        return Path(os.path.expanduser(self.policy.cache_path))


def _section(data: dict, name: str) -> dict:
    v = data.get(name)
    return v if isinstance(v, dict) else {}


def load_fast_config(path: Path | None = None) -> FastConfig:
    """Прочитать config.yaml для нужд enforce БЕЗ pydantic и БЕЗ создания файла.

    Горячий путь только читает: файл создаёт установка/``load_or_create``, а не
    проверка. Если файла нет или он битый — возвращаем дефолты (enforce тогда
    берёт block_fail_mode из самой политики, пути — дефолтные). Это то же
    поведение, что дал бы pydantic на пустом конфиге.
    """
    p = path or default_config_path()
    data: dict = {}
    try:
        if p.exists():
            loaded = yaml.safe_load(p.read_text())
            if isinstance(loaded, dict):
                data = loaded
    except OSError:
        data = {}

    audit = _section(data, "audit")
    policy = _section(data, "policy")
    return FastConfig(
        audit=_AuditView(
            max_bytes=int(audit.get("max_bytes", _DEFAULT_AUDIT_MAX_BYTES)),
            backup_count=int(audit.get("backup_count", _DEFAULT_AUDIT_BACKUP_COUNT)),
        ),
        policy=_PolicyView(
            cache_path=str(policy.get("cache_path", _DEFAULT_CACHE_PATH)),
            block_fail_mode=policy.get("block_fail_mode"),
        ),
    )
