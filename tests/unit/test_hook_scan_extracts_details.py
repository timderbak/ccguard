"""Hook scan: matcher/command/source/is_ccguard_owned правильно вытаскиваются.

Контекст: /admin/machines/<id> показывал "PreToolUse / PreToolUse / ..." без
malloc — пользователь не понимал свой ли это хук или чужой плагин. Эти поля
нужны UI для раскрываемой карточки.
"""

from __future__ import annotations

import json
from pathlib import Path

from ccguard.agent.scan.hooks import extract_from_settings
from ccguard.agent.scan.settings import parse_settings_file


def _settings(tmp_path: Path, data: dict) -> Path:
    f = tmp_path / "settings.json"
    f.write_text(json.dumps(data))
    return f


def test_matcher_and_command_and_source_carried(tmp_path: Path) -> None:
    f = _settings(
        tmp_path,
        {
            "hooks": {
                "PreToolUse": [
                    {
                        "matcher": "Bash|Write",
                        "hooks": [
                            {"type": "command", "command": "/root/.ccguard/bin/ccguard-enforce"}
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
    assert h.matcher == "Bash|Write"
    assert h.command == "/root/.ccguard/bin/ccguard-enforce"
    assert h.source == str(f)


def test_is_ccguard_owned_by_command_substring(tmp_path: Path) -> None:
    f = _settings(
        tmp_path,
        {
            "hooks": {
                "PreToolUse": [
                    {
                        "matcher": "Bash",
                        "hooks": [
                            {"type": "command", "command": "/root/.ccguard/bin/ccguard-enforce"}
                        ],
                    }
                ]
            }
        },
    )
    parsed = parse_settings_file(f, "user")
    hooks = extract_from_settings([parsed])
    assert hooks[0].is_ccguard_owned is True


def test_is_ccguard_owned_by_shim_marker(tmp_path: Path) -> None:
    """Команда не содержит 'ccguard', но первый файл — шим с маркером в шапке."""
    shim = tmp_path / "my-shim.sh"
    shim.write_text("#!/usr/bin/env bash\n# ccguard-shim v0.2\nexec /opt/foo\n")
    shim.chmod(0o755)
    f = _settings(
        tmp_path,
        {
            "hooks": {
                "PreToolUse": [
                    {
                        "matcher": "Bash",
                        "hooks": [{"type": "command", "command": str(shim)}],
                    }
                ]
            }
        },
    )
    parsed = parse_settings_file(f, "user")
    hooks = extract_from_settings([parsed])
    assert hooks[0].is_ccguard_owned is True


def test_is_ccguard_owned_false_for_third_party(tmp_path: Path) -> None:
    f = _settings(
        tmp_path,
        {
            "hooks": {
                "PreToolUse": [
                    {
                        "matcher": "Bash",
                        "hooks": [{"type": "command", "command": "python /root/.foo.py"}],
                    }
                ]
            }
        },
    )
    parsed = parse_settings_file(f, "user")
    hooks = extract_from_settings([parsed])
    assert hooks[0].is_ccguard_owned is False
