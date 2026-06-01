"""SettingsSource: exists + hooks_count + size_bytes для UI инвентаря.

Юзер открыл machine_detail и увидел просто 5 путей без контекста "есть/нет файла,
сколько хуков внутри". Эти поля закрывают этот пробел.
"""

from __future__ import annotations

import json
from pathlib import Path

from ccguard.agent.scan.settings import parse_settings_file


def test_existing_file_has_size_and_hooks_count(tmp_path: Path) -> None:
    f = tmp_path / "settings.json"
    payload = {
        "hooks": {
            "PreToolUse": [
                {"matcher": "Bash", "hooks": [{"type": "command", "command": "/a"}]},
                {"matcher": "Write", "hooks": [{"type": "command", "command": "/b"}]},
            ],
            "PostToolUse": [
                {"matcher": "*", "hooks": [{"type": "command", "command": "/c"}]},
            ],
        }
    }
    f.write_text(json.dumps(payload))
    parsed = parse_settings_file(f, "user")
    assert parsed.source.exists is True
    assert parsed.source.hooks_count == 3
    assert parsed.source.size_bytes is not None and parsed.source.size_bytes > 0


def test_missing_file_has_zero_counts(tmp_path: Path) -> None:
    f = tmp_path / "absent.json"
    parsed = parse_settings_file(f, "user")
    assert parsed.source.exists is False
    assert parsed.source.hooks_count == 0
    assert parsed.source.size_bytes == 0


def test_empty_file_zero_hooks(tmp_path: Path) -> None:
    f = tmp_path / "settings.json"
    f.write_text("{}")
    parsed = parse_settings_file(f, "user")
    assert parsed.source.exists is True
    assert parsed.source.hooks_count == 0
    assert parsed.source.size_bytes == 2
