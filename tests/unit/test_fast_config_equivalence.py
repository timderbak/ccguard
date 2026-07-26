"""FastConfig читает config.yaml так же, как pydantic AgentConfig.

hot_config дублирует четыре скалярных дефолта из config.py ради латентности
горячего пути. Дублирование безопасно ровно потому, что этот тест сверяет
результат обоих путей — расхождение дефолта падает здесь.
"""
from __future__ import annotations

from pathlib import Path

import yaml

from ccguard.agent.config import AgentConfig
from ccguard.agent.hot_config import load_fast_config


def _write(tmp: Path, data: dict) -> Path:
    p = tmp / "config.yaml"
    p.write_text(yaml.safe_dump(data))
    return p


def _assert_equivalent(path: Path) -> None:
    data = yaml.safe_load(path.read_text()) or {}
    pyd = AgentConfig.model_validate(data)
    fast = load_fast_config(path)
    assert fast.resolved_cache_path() == pyd.resolved_cache_path()
    assert fast.policy.block_fail_mode == pyd.policy.block_fail_mode
    assert fast.audit.max_bytes == pyd.audit.max_bytes
    assert fast.audit.backup_count == pyd.audit.backup_count


def test_empty_config_defaults_match(tmp_path: Path):
    # Пустой конфиг — все дефолты. Самый важный случай для дублированных дефолтов.
    _assert_equivalent(_write(tmp_path, {}))


def test_full_config_matches(tmp_path: Path):
    _assert_equivalent(_write(tmp_path, {
        "server": {"url": "https://ccguard.corp", "token": "ccg_x"},
        "audit": {"max_bytes": 1234, "backup_count": 9},
        "policy": {"cache_path": "/etc/ccguard/policy.yaml", "block_fail_mode": "closed"},
        "sync": {"interval_minutes": 30},
    }))


def test_partial_config_matches(tmp_path: Path):
    # Секция policy есть, но block_fail_mode не задан → None у обоих.
    _assert_equivalent(_write(tmp_path, {"policy": {"cache_path": "~/x/p.yaml"}}))


def test_missing_file_uses_defaults(tmp_path: Path):
    # Файла нет — FastConfig отдаёт дефолты, а не падает (enforce тогда берёт
    # block_fail_mode из самой политики).
    fast = load_fast_config(tmp_path / "nope.yaml")
    assert fast.policy.block_fail_mode is None
    assert fast.audit.backup_count == 5
