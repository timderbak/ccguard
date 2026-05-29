"""ToolUseEventIn accepts signals and defaults them when absent."""
from __future__ import annotations

from ccguard.schemas.tool_use import ToolUseEventIn


def test_signals_default_empty_when_absent():
    e = ToolUseEventIn(
        ts="2026-05-30T10:00:00+00:00",
        tool_name="Bash",
        fingerprint="0123456789abcdef",
        decision="allow",
        result_status="success",
    )
    assert e.signals == []


def test_signals_round_trip():
    e = ToolUseEventIn(
        ts="2026-05-30T10:00:00+00:00",
        tool_name="Bash",
        fingerprint="0123456789abcdef",
        decision="allow",
        result_status="success",
        signals=["cred.read.aws"],
    )
    assert e.signals == ["cred.read.aws"]
    assert "cred.read.aws" in e.model_dump_json()
