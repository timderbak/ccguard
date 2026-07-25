"""Личность агента: «кто действовал и с какими правами».

Claude Code кладёт в payload каждого хука поля, которые раньше выбрасывались:
режим прав (permission_mode), какой субагент действует (agent_type/agent_id) и
связку действий с одним запросом человека (prompt_id).

Самое важное здесь — permission_mode. Значения ``dontAsk`` и
``bypassPermissions`` означают, что агент работал БЕЗ подтверждений человеком:
для ИБ это то же, что «сотрудник отключил защиту», и раньше мы этого не видели
вообще.

Проверяется весь путь: payload хука → локальный буфер → отправка на сервер,
плюс обратная совместимость (старый агент не шлёт полей — событие принимается
без атрибуции, а не отбраковывается и не помечается ошибочно).
"""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from ccguard.agent.audit_hook.buffer import ToolBufferDB
from ccguard.agent.audit_hook.hook_main import main_cli

_ALL_MODES = ("default", "plan", "acceptEdits", "auto", "dontAsk", "bypassPermissions")
# Режимы, в которых агент действует без подтверждения человеком.
_UNATTENDED = ("dontAsk", "bypassPermissions")


@pytest.fixture
def buffer_path(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    cfg = tmp_path / "cfg"
    cfg.mkdir()
    monkeypatch.setattr("ccguard.agent.audit_hook.hook_main.default_config_dir", lambda: cfg)
    # флашер не должен уходить в сеть из теста
    monkeypatch.setattr("ccguard.agent.audit_hook.hook_main.maybe_spawn_flusher", lambda **_: None)
    return cfg / "audit_buffer.db"


def _payload(**extra) -> str:
    base = {
        "hook_event_name": "PostToolUse",
        "session_id": "sess-1",
        "tool_name": "Bash",
        "tool_input": {"command": "ls -la"},
        "tool_response": {"success": True},
    }
    base.update(extra)
    return json.dumps(base)


def _one_row(buffer_path: Path):
    with ToolBufferDB(buffer_path) as buf:
        rows = buf.drain()
    assert len(rows) == 1
    return rows[0]


# --- сбор из payload хука ----------------------------------------------------


@pytest.mark.parametrize("mode", _ALL_MODES)
def test_every_permission_mode_is_captured(buffer_path: Path, mode: str):
    assert main_cli(_payload(permission_mode=mode)) == 0
    assert _one_row(buffer_path)["permission_mode"] == mode


def test_unattended_modes_are_distinguishable(buffer_path: Path):
    # Ради этого всё и делается: режим без подтверждений должен быть виден.
    assert main_cli(_payload(permission_mode="bypassPermissions")) == 0
    assert _one_row(buffer_path)["permission_mode"] in _UNATTENDED


def test_subagent_identity_captured(buffer_path: Path):
    assert main_cli(_payload(agent_type="security-reviewer", agent_id="agt_42")) == 0
    row = _one_row(buffer_path)
    assert row["agent_type"] == "security-reviewer"
    assert row["agent_id"] == "agt_42"


def test_prompt_id_captured(buffer_path: Path):
    assert main_cli(_payload(prompt_id="550e8400-e29b-41d4-a716-446655440000")) == 0
    assert _one_row(buffer_path)["prompt_id"].startswith("550e8400")


def test_main_agent_has_no_subagent_fields(buffer_path: Path):
    # Отсутствие agent_type означает «действовал основной агент», а не ошибку.
    assert main_cli(_payload(permission_mode="default")) == 0
    row = _one_row(buffer_path)
    assert row["agent_type"] is None
    assert row["agent_id"] is None


# --- обратная совместимость и устойчивость к мусору --------------------------


def test_legacy_payload_without_identity_still_ingests(buffer_path: Path):
    # Старый Claude Code / старый агент: полей нет — событие всё равно попадает
    # в буфер, просто без атрибуции.
    assert main_cli(_payload()) == 0
    row = _one_row(buffer_path)
    assert row["permission_mode"] is None
    assert row["prompt_id"] is None
    assert row["tool_name"] == "Bash"  # само событие не потеряно


@pytest.mark.parametrize("bad", [123, {"a": 1}, [], True, None])
def test_non_string_identity_values_become_none(buffer_path: Path, bad):
    # Payload приходит извне: неверный тип не должен ломать разбор.
    assert main_cli(_payload(permission_mode=bad, agent_type=bad)) == 0
    row = _one_row(buffer_path)
    assert row["permission_mode"] is None
    assert row["agent_type"] is None


def test_overlong_values_are_truncated_to_wire_limits(buffer_path: Path):
    # Обрезаем по тем же пределам, что и в wire-схеме, иначе сервер отбракует
    # всю пачку событий при валидации.
    assert main_cli(_payload(permission_mode="x" * 500, agent_type="y" * 500)) == 0
    row = _one_row(buffer_path)
    assert len(row["permission_mode"]) == 32
    assert len(row["agent_type"]) == 128


def test_unknown_future_mode_passes_through(buffer_path: Path):
    # Anthropic добавляет режимы (auto появился позже) — незнакомое значение
    # должно доехать как есть, а не потеряться.
    assert main_cli(_payload(permission_mode="someFutureMode")) == 0
    assert _one_row(buffer_path)["permission_mode"] == "someFutureMode"


# --- провод до сервера -------------------------------------------------------


def test_wire_schema_carries_identity():
    from ccguard.schemas.tool_use import ToolUseEventIn

    e = ToolUseEventIn(
        ts="2026-07-25T10:00:00Z", tool_name="Bash", fingerprint="a" * 16,
        decision="allow", result_status="success",
        permission_mode="bypassPermissions", agent_type="Explore",
        agent_id="agt_1", prompt_id="p-1",
    )
    assert e.permission_mode == "bypassPermissions"
    assert e.agent_type == "Explore"


def test_wire_schema_identity_optional():
    # v0.1/v0.2 агент: полей нет — схема обязана валидироваться.
    from ccguard.schemas.tool_use import ToolUseEventIn

    e = ToolUseEventIn(
        ts="2026-07-25T10:00:00Z", tool_name="Bash", fingerprint="a" * 16,
        decision="allow", result_status="success",
    )
    assert e.permission_mode is None
    assert e.agent_type is None
    assert e.prompt_id is None
