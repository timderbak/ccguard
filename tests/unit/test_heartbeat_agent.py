"""ТЗ-07: agent-side heartbeat — self-integrity check + payload/send."""
from __future__ import annotations

import json
from pathlib import Path

import httpx
import pytest

from ccguard.agent import heartbeat


def _write_settings(path: Path, hooks: dict) -> None:
    path.write_text(json.dumps({"hooks": hooks}))


def test_hooks_intact_true_when_ccguard_hook_present(tmp_path: Path) -> None:
    settings = tmp_path / "settings.json"
    _write_settings(
        settings,
        {
            "PreToolUse": [
                {"hooks": [{"type": "command", "command": "ccguard enforce"}]}
            ]
        },
    )
    assert heartbeat.check_hooks_intact(settings) is True


def test_hooks_intact_false_when_ccguard_hook_absent(tmp_path: Path) -> None:
    settings = tmp_path / "settings.json"
    _write_settings(
        settings,
        {"PreToolUse": [{"hooks": [{"type": "command", "command": "other-tool"}]}]},
    )
    assert heartbeat.check_hooks_intact(settings) is False


def test_hooks_intact_unknown_when_settings_missing(tmp_path: Path) -> None:
    """Unreadable settings → None (unknown), NOT False — avoid false 'removed'."""
    assert heartbeat.check_hooks_intact(tmp_path / "nope.json") is None


# --- C2: hook-config hash attestation (stronger than the substring bool) ------


def test_hooks_hash_stable_and_deterministic(tmp_path: Path) -> None:
    settings = tmp_path / "settings.json"
    cfg = {"PreToolUse": [{"matcher": "*", "hooks": [
        {"type": "command", "command": "~/.ccguard/bin/ccguard-enforce"}]}]}
    _write_settings(settings, cfg)
    h1 = heartbeat.compute_hooks_hash(settings)
    _write_settings(settings, cfg)  # rewrite identical
    h2 = heartbeat.compute_hooks_hash(settings)
    assert h1 is not None and h1 == h2


def test_hooks_hash_changes_on_repoint_to_decoy_shim(tmp_path: Path) -> None:
    """The substring bool can't see a repoint to a no-op shim whose path still
    contains 'ccguard'; the hash MUST. This is the core C2 win."""
    settings = tmp_path / "settings.json"
    _write_settings(settings, {"PreToolUse": [{"matcher": "*", "hooks": [
        {"type": "command", "command": "~/.ccguard/bin/ccguard-enforce"}]}]})
    real = heartbeat.compute_hooks_hash(settings)
    # Repoint to a decoy shim — check_hooks_intact still True (substring present)
    _write_settings(settings, {"PreToolUse": [{"matcher": "*", "hooks": [
        {"type": "command", "command": "~/.ccguard/bin/ccguard-noop-shim"}]}]})
    decoy = heartbeat.compute_hooks_hash(settings)
    assert heartbeat.check_hooks_intact(settings) is True  # bool is fooled
    assert real is not None and decoy is not None and real != decoy  # hash is not


def test_hooks_hash_none_when_no_ccguard_hook(tmp_path: Path) -> None:
    """Removal is covered by the bool (hooks_intact=False); the hash is for the
    present-but-changed case, so no ccguard hook → None."""
    settings = tmp_path / "settings.json"
    _write_settings(settings, {"PreToolUse": [{"hooks": [
        {"type": "command", "command": "other-tool"}]}]})
    assert heartbeat.compute_hooks_hash(settings) is None


def test_hooks_hash_none_when_settings_missing(tmp_path: Path) -> None:
    assert heartbeat.compute_hooks_hash(tmp_path / "nope.json") is None


def test_build_payload_shape() -> None:
    p = heartbeat.build_heartbeat(
        machine_id="m1", agent_version="0.2", hooks_intact=True,
        expected_interval_sec=900, hooks_hash="abc123",
    )
    assert p["machine_id"] == "m1"
    assert p["hooks_intact"] is True
    assert p["expected_interval_sec"] == 900
    assert p["hooks_hash"] == "abc123"
    assert "tool_input" not in p  # privacy: no raw data in heartbeat


def test_send_heartbeat_posts_and_never_raises(monkeypatch) -> None:
    captured: dict = {}

    class _Client:
        def __init__(self, *a, **k) -> None: ...
        def __enter__(self): return self
        def __exit__(self, *a) -> None: ...
        def post(self, url, *, content, headers):
            captured["url"] = url
            captured["body"] = json.loads(content)
            return httpx.Response(200, request=httpx.Request("POST", url))

    monkeypatch.setattr(httpx, "Client", _Client)
    ok = heartbeat.send_heartbeat(
        server_url="http://test", token="tok",
        payload={"machine_id": "m1", "hooks_intact": True},
    )
    assert ok is True
    assert captured["url"] == "http://test/api/v1/heartbeat"
    assert captured["body"]["machine_id"] == "m1"


def test_send_heartbeat_swallows_errors(monkeypatch) -> None:
    class _Boom:
        def __init__(self, *a, **k) -> None: ...
        def __enter__(self): return self
        def __exit__(self, *a) -> None: ...
        def post(self, *a, **k): raise httpx.ConnectError("down")

    monkeypatch.setattr(httpx, "Client", _Boom)
    assert heartbeat.send_heartbeat(
        server_url="http://test", token="tok", payload={"machine_id": "m1"}
    ) is False
