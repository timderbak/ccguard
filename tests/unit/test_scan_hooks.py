"""Hooks: извлечение из settings.json + детект disableAllHooks."""

from __future__ import annotations

import json
from pathlib import Path

from ccguard.agent.scan.hooks import detect_disable_all_hooks, extract_from_settings
from ccguard.agent.scan.settings import parse_settings_file


def _settings(tmp_path: Path, data: dict) -> Path:
    f = tmp_path / "settings.json"
    f.write_text(json.dumps(data))
    return f


def test_extract_command_hook(tmp_path: Path) -> None:
    f = _settings(
        tmp_path,
        {
            "hooks": {
                "PreToolUse": [
                    {
                        "matcher": "Bash",
                        "hooks": [
                            {"type": "command", "command": "/usr/local/bin/lint", "timeout": 5}
                        ],
                    }
                ]
            }
        },
    )
    parsed = parse_settings_file(f, "user")
    hooks = extract_from_settings([parsed])
    assert len(hooks) == 1
    h = hooks[0]
    assert h.event == "PreToolUse"
    assert h.matcher == "Bash"
    assert h.type == "command"
    assert h.command == "/usr/local/bin/lint"
    assert h.timeout_sec == 5


def test_extract_multiple_events_and_matchers(tmp_path: Path) -> None:
    f = _settings(
        tmp_path,
        {
            "hooks": {
                "PreToolUse": [
                    {"matcher": "Bash", "hooks": [{"type": "command", "command": "a"}]},
                    {"matcher": "mcp__.*", "hooks": [{"type": "command", "command": "b"}]},
                ],
                "PostToolUse": [
                    {"matcher": "Write", "hooks": [{"type": "command", "command": "c"}]}
                ],
            }
        },
    )
    parsed = parse_settings_file(f, "user")
    hooks = extract_from_settings([parsed])
    assert len(hooks) == 3
    events = {h.event for h in hooks}
    assert events == {"PreToolUse", "PostToolUse"}


def test_unknown_event_ignored(tmp_path: Path) -> None:
    f = _settings(
        tmp_path,
        {"hooks": {"WeirdEvent": [{"hooks": [{"type": "command", "command": "x"}]}]}},
    )
    parsed = parse_settings_file(f, "user")
    assert extract_from_settings([parsed]) == []


def test_unknown_hook_type_ignored(tmp_path: Path) -> None:
    f = _settings(
        tmp_path,
        {
            "hooks": {
                "PreToolUse": [
                    {"matcher": "Bash", "hooks": [{"type": "weird", "command": "x"}]}
                ]
            }
        },
    )
    parsed = parse_settings_file(f, "user")
    assert extract_from_settings([parsed]) == []


def test_disable_all_hooks_detected(tmp_path: Path) -> None:
    f = _settings(tmp_path, {"disableAllHooks": True})
    parsed = parse_settings_file(f, "user")
    assert detect_disable_all_hooks([parsed]) is True


def test_disable_all_hooks_false_by_default(tmp_path: Path) -> None:
    f = _settings(tmp_path, {"hooks": {}})
    parsed = parse_settings_file(f, "user")
    assert detect_disable_all_hooks([parsed]) is False
