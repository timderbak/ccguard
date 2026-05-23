"""Парсинг settings.json: валидный, битый, отсутствующий."""

from __future__ import annotations

import json
from pathlib import Path

from ccguard.agent.scan.settings import parse_settings_file


def test_missing_file(tmp_path: Path) -> None:
    parsed = parse_settings_file(tmp_path / "absent.json", "user")
    assert parsed.source.exists is False
    assert parsed.data is None
    assert parsed.source.parse_error is None


def test_valid_json(tmp_path: Path) -> None:
    f = tmp_path / "settings.json"
    f.write_text(json.dumps({"permissions": {"allow": ["Bash"]}}))
    parsed = parse_settings_file(f, "user")
    assert parsed.source.exists is True
    assert parsed.source.parse_error is None
    assert parsed.data == {"permissions": {"allow": ["Bash"]}}


def test_broken_json(tmp_path: Path) -> None:
    f = tmp_path / "settings.json"
    f.write_text("{not valid json")
    parsed = parse_settings_file(f, "user")
    assert parsed.source.exists is True
    assert parsed.source.parse_error is not None
    assert "json decode" in parsed.source.parse_error
    assert parsed.data is None


def test_top_level_not_object(tmp_path: Path) -> None:
    f = tmp_path / "settings.json"
    f.write_text("[1, 2, 3]")
    parsed = parse_settings_file(f, "user")
    assert parsed.source.parse_error is not None
    assert "object" in parsed.source.parse_error
    assert parsed.data is None


def test_empty_file(tmp_path: Path) -> None:
    f = tmp_path / "settings.json"
    f.write_text("")
    parsed = parse_settings_file(f, "user")
    assert parsed.source.exists is True
    assert parsed.source.parse_error is None
    assert parsed.data == {}
