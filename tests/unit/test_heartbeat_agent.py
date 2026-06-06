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


def test_build_payload_shape() -> None:
    p = heartbeat.build_heartbeat(
        machine_id="m1", agent_version="0.2", hooks_intact=True,
        expected_interval_sec=900,
    )
    assert p["machine_id"] == "m1"
    assert p["hooks_intact"] is True
    assert p["expected_interval_sec"] == 900
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
