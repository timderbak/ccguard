"""Agent-side overrides loader: defensive parsing, missing-file safety."""
from __future__ import annotations

from pathlib import Path

import yaml

from ccguard.agent.signals.overrides_loader import load_overrides


def _write(tmp_path: Path, doc: dict | str) -> Path:
    p = tmp_path / "policy.yaml"
    if isinstance(doc, str):
        p.write_text(doc)
    else:
        p.write_text(yaml.safe_dump(doc))
    return p


def test_missing_file_returns_empty(tmp_path):
    assert load_overrides(tmp_path / "absent.yaml") == []


def test_malformed_yaml_returns_empty(tmp_path):
    p = _write(tmp_path, "{not: valid: yaml: at:: all]")
    assert load_overrides(p) == []


def test_policy_without_overrides_returns_empty(tmp_path):
    p = _write(tmp_path, {"meta": {"revision": 1}})
    assert load_overrides(p) == []


def test_loads_valid_overrides(tmp_path):
    p = _write(tmp_path, {
        "meta": {"revision": 1},
        "signal_overrides": [
            {"id": "cred.read.session_cookie", "attack_technique": "T1539",
             "pattern": r"cookies\.binarycookies", "description": "browser"},
            {"id": "x.y", "attack_technique": "T1001",
             "pattern": "deadbeef", "description": "x"},
        ],
    })
    rows = load_overrides(p)
    assert len(rows) == 2
    assert rows[0]["id"] == "cred.read.session_cookie"


def test_malformed_entries_dropped(tmp_path):
    p = _write(tmp_path, {
        "meta": {"revision": 1},
        "signal_overrides": [
            {"id": "valid.one", "attack_technique": "T1001",
             "pattern": "ok", "description": "x"},
            {"id": "missing.keys"},  # incomplete
            "not even a dict",
            {"id": "", "attack_technique": "T1", "pattern": "p", "description": "d"},  # empty id
        ],
    })
    rows = load_overrides(p)
    assert [r["id"] for r in rows] == ["valid.one"]
