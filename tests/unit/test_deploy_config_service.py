"""Готовый конфиг для массовой раскатки.

Главное, что здесь проверяется, — не форматирование, а два свойства:

* в выдаче нет и не может появиться реального токена (один токен на образ
  означает, что его утечка компрометирует весь флот, а отзыв — останавливает);
* ожидаемый отпечаток хуков считается той же функцией, что на агенте, — иначе
  сверка «на машине не тот конфиг» давала бы вечное расхождение без атаки.
"""
from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta

import pytest
from sqlmodel import Session

from ccguard.agent import heartbeat as _hb
from ccguard.server.db.models import Machine
from ccguard.server.db.session import init_db, make_engine
from ccguard.server.services import deploy_config_service as dcs
from ccguard.server.services import settings_service


def _engine():
    eng = make_engine("sqlite://")
    init_db(eng)
    return eng


# --- содержимое конфига -----------------------------------------------------


def test_managed_settings_contain_both_hooks():
    data = dcs.build_managed_settings("linux")
    assert set(data["hooks"]) == {"PreToolUse", "PostToolUse"}
    commands = [
        h["command"]
        for entries in data["hooks"].values()
        for e in entries
        for h in e["hooks"]
    ]
    assert any("ccguard-enforce" in c for c in commands)
    assert any("ccguard-audit" in c for c in commands)


def test_deployed_config_locks_the_sandbox():
    # Раскатываемый managed-конфиг теперь не только прошивает хуки, но и ВЛАДЕЕТ
    # песочницей: форсит изоляцию + запрещает bypass — «пустышку» не снести.
    linux = dcs.build_managed_settings("linux")
    assert linux["sandbox"]["enabled"] is True
    assert linux["sandbox"]["failIfUnavailable"] is True
    assert linux["permissions"]["disableBypassPermissionsMode"] == "disable"
    # macOS (platform=darwin) тоже под sandbox-lock.
    assert dcs.build_managed_settings("darwin")["sandbox"]["enabled"] is True
    # Windows: песочницы у Claude Code нет → sandbox-блок не кладём (иначе кирпич),
    # но запрет bypass остаётся.
    win = dcs.build_managed_settings("win32")
    assert "sandbox" not in win
    assert win["permissions"]["disableBypassPermissionsMode"] == "disable"


def test_resolve_egress_allowlist_parses_and_dedupes():
    eng = _engine()
    with Session(eng) as s:
        assert dcs.resolve_egress_allowlist(s) == []  # не задано → пусто
        settings_service.set_setting(
            s, dcs.EGRESS_ALLOWLIST_KEY, "pypi.org, github.com\nregistry.npmjs.org pypi.org/",
        )
        got = dcs.resolve_egress_allowlist(s)
    assert got == ["pypi.org", "github.com", "registry.npmjs.org"]  # dedupe + чистка


def test_bundle_egress_default_deny_when_org_sets_allowlist():
    eng = _engine()
    with Session(eng) as s:
        settings_service.set_setting(s, dcs.EGRESS_ALLOWLIST_KEY, "pypi.org, github.com")
        bundle = dcs.build_bundle(s, platform="linux")
    net = bundle["managed_settings"]["sandbox"]["network"]
    assert net["allowManagedDomainsOnly"] is True
    assert net["allowedDomains"][0] == "api.anthropic.com"  # вшит всегда
    assert {"pypi.org", "github.com"} <= set(net["allowedDomains"])
    assert bundle["egress_allowlist"] == ["pypi.org", "github.com"]
    # Список попал и в скрипт установки (иначе на машине был бы другой конфиг).
    assert "pypi.org" in bundle["install_script"]


def test_bundle_egress_not_narrowed_by_default():
    eng = _engine()
    with Session(eng) as s:
        bundle = dcs.build_bundle(s, platform="linux")
    assert "network" not in bundle["managed_settings"]["sandbox"]  # день-в-день не ломаем
    assert bundle["egress_allowlist"] == []


def test_shim_paths_match_the_path_baked_into_the_shim():
    # Шимы сами ищут самостоятельный бинарник в /opt/ccguard/bin — раскатка
    # обязана класть файлы туда же, иначе бинарник не подхватится.
    enforce, audit = dcs.shim_paths("linux")
    assert str(enforce).startswith("/opt/ccguard/bin")
    assert str(audit).startswith("/opt/ccguard/bin")


def test_unsupported_platform_is_refused():
    with pytest.raises(ValueError):
        dcs.shim_paths("plan9")


# --- токен ------------------------------------------------------------------


def test_bundle_never_contains_a_real_token():
    eng = _engine()
    with Session(eng) as s:
        b = dcs.build_bundle(s, platform="linux")
    blob = json.dumps({k: v for k, v in b.items()}, default=str)
    assert dcs.TOKEN_PLACEHOLDER in b["agent_config"]
    assert "ccg_" not in blob, "реальный токен не должен попадать в раскатку"


def test_install_script_takes_the_token_from_the_environment():
    eng = _engine()
    with Session(eng) as s:
        b = dcs.build_bundle(s, platform="linux")
    script = b["install_script"]
    assert "CCGUARD_AGENT_TOKEN" in script
    assert dcs.TOKEN_PLACEHOLDER in script


# --- адрес сервера ----------------------------------------------------------


def test_configured_url_wins_over_the_guess():
    eng = _engine()
    with Session(eng) as s:
        settings_service.set_setting(s, dcs.SERVER_URL_KEY, "https://ccguard.corp/")
        b = dcs.build_bundle(s, platform="linux", fallback_url="http://10.0.0.5:8000")
    assert b["server_url"] == "https://ccguard.corp"
    assert b["server_url_guessed"] is False


def test_guessed_url_is_flagged_as_guessed():
    # За обратным прокси адрес из запроса часто внутренний, и агенты по нему не
    # достучатся. Выдавать догадку за истину нельзя.
    eng = _engine()
    with Session(eng) as s:
        b = dcs.build_bundle(s, platform="linux", fallback_url="http://10.0.0.5:8000")
    assert b["server_url"] == "http://10.0.0.5:8000"
    assert b["server_url_guessed"] is True


def test_server_url_lands_in_agent_config():
    eng = _engine()
    with Session(eng) as s:
        settings_service.set_setting(s, dcs.SERVER_URL_KEY, "https://ccguard.corp")
        b = dcs.build_bundle(s, platform="linux")
    assert "https://ccguard.corp" in b["agent_config"]


# --- ожидаемый отпечаток ----------------------------------------------------


def test_expected_hash_matches_what_an_agent_would_report(tmp_path):
    # Сервер и агент обязаны считать одинаково: разойдись формулы — и сверка
    # показывала бы расхождение на каждой машине без всякой атаки.
    expected = dcs.expected_hooks_hash("linux")
    f = tmp_path / "managed-settings.json"
    f.write_text(json.dumps(dcs.build_managed_settings("linux")))
    assert expected is not None
    assert _hb.compute_hooks_hash(f) == expected


def test_hash_differs_between_platforms():
    # Пути к шимам разные, значит и отпечаток разный — иначе сверка на macOS
    # молча принимала бы линуксовый конфиг.
    assert dcs.expected_hooks_hash("linux") != dcs.expected_hooks_hash("win32")


# --- сверка с флотом --------------------------------------------------------


def _machine(s, mid, hooks_hash):
    now = datetime.now(UTC).replace(tzinfo=None)
    s.add(Machine(machine_id=mid, machine_label=mid, first_seen=now, last_seen=now,
                  agent_version="0.3", last_heartbeat_at=now - timedelta(minutes=1),
                  hooks_hash=hooks_hash))
    s.commit()


def test_drift_finds_a_machine_with_a_different_config():
    eng = _engine()
    with Session(eng) as s:
        _machine(s, "m-ok", dcs.expected_hooks_hash("linux"))
        _machine(s, "m-bad", "deadbeef" * 8)
        rows = dcs.config_drift(s, platform="linux")
    assert [r["machine_id"] for r in rows] == ["m-bad"]


def test_machine_without_a_hash_is_not_called_drifted():
    # «Не доложила» и «доложила другое» — разные утверждения. Смешивать их
    # значит выдавать неизвестность за расхождение.
    eng = _engine()
    with Session(eng) as s:
        _machine(s, "m-quiet", None)
        rows = dcs.config_drift(s, platform="linux")
    assert rows == []
