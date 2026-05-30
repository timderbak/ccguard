"""Signal overrides plumbing: schema round-trip + extractor merge + precedence."""
from __future__ import annotations

import pytest

from ccguard.agent.signals.extractor import extract_signals
from ccguard.schemas import Policy
from ccguard.schemas.policy import PolicyMeta, SignalOverrideIn


def _empty_policy_dict() -> dict:
    return {"meta": {"revision": 1, "updated_at": "2026-05-30T00:00:00Z"}}


def test_signal_override_schema_round_trips():
    raw = {
        "id": "cred.read.session_cookie",
        "attack_technique": "T1539",
        "pattern": r"cookies\.binarycookies",
        "description": "Browser cookies",
    }
    obj = SignalOverrideIn.model_validate(raw)
    assert obj.id == "cred.read.session_cookie"
    assert obj.model_dump()["pattern"] == r"cookies\.binarycookies"


def test_policy_accepts_optional_signal_overrides_field():
    p_dict = _empty_policy_dict()
    p_dict["signal_overrides"] = [
        {
            "id": "cred.read.session_cookie",
            "attack_technique": "T1539",
            "pattern": "cookies",
            "description": "x",
        }
    ]
    p = Policy.model_validate(p_dict)
    assert len(p.signal_overrides) == 1
    assert p.signal_overrides[0].id == "cred.read.session_cookie"


def test_policy_default_signal_overrides_is_empty_list():
    p = Policy.model_validate(_empty_policy_dict())
    assert p.signal_overrides == []


def test_extractor_fires_an_override_signal():
    overrides = [
        {
            "id": "cred.read.session_cookie",
            "attack_technique": "T1539",
            "pattern": r"cookies\.binarycookies",
            "description": "x",
        }
    ]
    fired = extract_signals(
        "Read",
        {"file_path": "/Users/x/Library/Cookies/Cookies.binarycookies"},
        overrides=overrides,
    )
    assert "cred.read.session_cookie" in fired


def test_extractor_override_replaces_baked_signal_with_same_id():
    # Override the AWS regex to a non-matching pattern; baked AWS pattern would
    # match, but with the override it must NOT fire.
    overrides = [
        {
            "id": "cred.read.aws",
            "attack_technique": "T1552.001",
            "pattern": r"this-never-matches-anything-xyz123",
            "description": "hotfix override",
        }
    ]
    fired = extract_signals(
        "Bash",
        {"command": "cat ~/.aws/credentials"},
        overrides=overrides,
    )
    assert "cred.read.aws" not in fired


def test_extractor_ignores_malformed_override():
    overrides = [
        {"id": "bad.regex", "attack_technique": "T9999", "pattern": "(unclosed", "description": "x"},
        {"id": "valid.one", "attack_technique": "T1001", "pattern": "deadbeef", "description": "x"},
    ]
    fired = extract_signals("Bash", {"command": "deadbeef"}, overrides=overrides)
    assert "valid.one" in fired
    assert "bad.regex" not in fired


def test_extractor_without_overrides_unchanged():
    """Existing call-site contract (no overrides param) must still work."""
    fired = extract_signals("Bash", {"command": "cat ~/.aws/credentials"})
    assert "cred.read.aws" in fired
