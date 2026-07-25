"""Hardened tier (privilege boundary) — pin ccguard hooks in Claude Code's
root-owned managed-settings.json + make shim/policy root-owned & immutable.

The plan/script generation is pure and tested here; APPLYING it requires root
and is a field-test on the endpoint (like daemon_install's real subprocess path).
"""
from __future__ import annotations

from pathlib import Path

from ccguard.agent import harden
from ccguard.agent import install as _install


def test_managed_settings_path_per_os() -> None:
    # Confirmed against Claude Code v2.1.178 (policy/MDM managed-settings source).
    assert (
        harden.managed_settings_path("darwin")
        == "/Library/Application Support/ClaudeCode/managed-settings.json"
    )
    assert harden.managed_settings_path("linux") == "/etc/claude-code/managed-settings.json"
    assert harden.managed_settings_path("unknown-os") is None


def test_build_managed_settings_pins_both_hooks() -> None:
    data = harden.build_managed_settings(
        Path("/opt/ccguard/bin/ccguard-enforce"),
        Path("/opt/ccguard/bin/ccguard-audit"),
    )
    hooks = data["hooks"]
    # PreToolUse enforce hook over the real matchers, pointing at the enforce shim
    pre_cmds = [
        h["command"]
        for entry in hooks["PreToolUse"]
        for h in entry["hooks"]
    ]
    assert pre_cmds and all(c == "/opt/ccguard/bin/ccguard-enforce" for c in pre_cmds)
    pre_matchers = {entry["matcher"] for entry in hooks["PreToolUse"]}
    assert set(_install.HOOK_MATCHERS) <= pre_matchers
    # PostToolUse audit hook
    post_cmds = [h["command"] for entry in hooks["PostToolUse"] for h in entry["hooks"]]
    assert post_cmds == ["/opt/ccguard/bin/ccguard-audit"]


def test_immutability_argv_per_os() -> None:
    assert harden.immutability_argv("/p", "linux") == ["chattr", "+i", "/p"]
    assert harden.immutability_argv("/p", "darwin") == ["chflags", "schg", "/p"]
    assert harden.immutability_argv("/p", "unknown-os") is None


def test_harden_plan_covers_managed_shim_and_policy() -> None:
    plan = harden.harden_plan(
        platform="darwin",
        enforce_shim=Path("/opt/ccguard/bin/ccguard-enforce"),
        audit_shim=Path("/opt/ccguard/bin/ccguard-audit"),
        policy_path=Path("/opt/ccguard/policy.yaml"),
    )
    # The managed-settings file is written with the pinned hooks.
    writes = [s for s in plan if s.kind == "write_file"]
    assert any(
        s.path == harden.managed_settings_path("darwin") and "ccguard-enforce" in s.content
        for s in writes
    )
    # Immutability is applied to the managed file, the shim AND the policy.
    runs = [tuple(s.argv) for s in plan if s.kind == "run"]
    flat = " ".join(" ".join(a) for a in runs)
    assert "chflags schg" in flat
    for asset in ("ccguard-enforce", "policy.yaml", "managed-settings.json"):
        assert asset in flat, f"{asset} not hardened in plan"
    # Root ownership is established (privilege boundary).
    assert "chown" in flat and "root" in flat


def test_render_script_is_reviewable_sudo_bash() -> None:
    plan = harden.harden_plan(
        platform="darwin",
        enforce_shim=Path("/opt/ccguard/bin/ccguard-enforce"),
        audit_shim=Path("/opt/ccguard/bin/ccguard-audit"),
        policy_path=Path("/opt/ccguard/policy.yaml"),
    )
    script = harden.render_script(plan)
    assert script.startswith("#!/usr/bin/env bash")
    assert "set -euo pipefail" in script
    assert "managed-settings.json" in script
    assert "chflags schg" in script


# --- защита среды запуска ---------------------------------------------------


def test_runtime_root_is_taken_away_from_the_user():
    # Защищать хук и оставлять запускаемый им код открытым на запись — то же
    # самое, что закрыть дверь и оставить окно: подменяется не хук, а модуль,
    # который хук вызовет.
    steps = harden.harden_plan(
        platform="linux",
        enforce_shim=Path("/opt/ccguard/bin/ccguard-enforce"),
        audit_shim=Path("/opt/ccguard/bin/ccguard-audit"),
        policy_path=Path("/etc/ccguard/policy.yaml"),
        runtime_root=Path("/opt/ccguard"),
    )
    argvs = [" ".join(s.argv) for s in steps if s.kind == "run"]
    assert "chown -R root:root /opt/ccguard" in argvs
    assert "chmod -R go-w /opt/ccguard" in argvs


def test_runtime_root_is_optional_and_off_by_default():
    # Обратная совместимость: старый вызов без указания среды запуска не должен
    # внезапно начать менять права на каталогах, о которых не просили.
    steps = harden.harden_plan(
        platform="linux",
        enforce_shim=Path("/opt/ccguard/bin/ccguard-enforce"),
        audit_shim=Path("/opt/ccguard/bin/ccguard-audit"),
        policy_path=Path("/etc/ccguard/policy.yaml"),
    )
    assert not any("-R" in s.argv for s in steps if s.kind == "run")


def test_runtime_root_is_not_made_immutable():
    # Неизменяемый флаг на дереве файлов превратил бы обновление агента в
    # ручную операцию с правами администратора на каждой машине.
    steps = harden.runtime_lock_steps(Path("/opt/ccguard"), platform="linux")
    assert not any("chattr" in s.argv for s in steps)


def test_deploy_script_locks_the_runtime_too():
    # Скрипт раскатки и план укрепления должны закрывать одно и то же: иначе
    # машины, поставленные централизованно, остались бы с открытым окном.
    from sqlmodel import Session

    from ccguard.server.db.session import init_db, make_engine
    from ccguard.server.services import deploy_config_service as dcs

    eng = make_engine("sqlite://")
    init_db(eng)
    with Session(eng) as s:
        script = dcs.build_bundle(s, platform="linux")["install_script"]
    assert "chown -R root:root /opt/ccguard" in script
    assert "chmod -R go-w /opt/ccguard" in script
