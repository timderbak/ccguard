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
