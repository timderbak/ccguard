"""Unit tests for enforce_block_service.list_recent_blocks.

Surfaces the AuditRecord stream (deny + fail_open enforcement events) for a
machine so anti-tamper hard.* blocks become visible in the console.
"""
from __future__ import annotations

from datetime import UTC, datetime, timedelta

from sqlmodel import Session

from ccguard.server.db.models import AuditRecord
from ccguard.server.db.session import init_db, make_engine
from ccguard.server.services.enforce_block_service import list_recent_blocks


def _engine():
    eng = make_engine("sqlite://")
    init_db(eng)
    return eng


def _rec(machine_id, *, rule_id, reason, fail_open, when, fp) -> AuditRecord:
    return AuditRecord(
        machine_id=machine_id,
        timestamp=when,
        received_at=when,
        tool_name="Bash",
        decision="deny",
        rule_id=rule_id,
        reason=reason,
        fail_open=fail_open,
        tool_input_fingerprint=fp,
    )


def test_list_recent_blocks_deny_and_fail_open_newest_first() -> None:
    eng = _engine()
    now = datetime.now(UTC)
    with Session(eng) as s:
        s.add(_rec("m1", rule_id="hard.fs_wipe", reason="rm -rf /", fail_open=False,
                   when=now - timedelta(hours=2), fp="a"))
        s.add(_rec("m1", rule_id=None, reason="policy unavailable", fail_open=True,
                   when=now - timedelta(hours=1), fp="b"))
        s.add(_rec("m2", rule_id="hard.reverse_shell", reason="revshell", fail_open=False,
                   when=now, fp="c"))  # other machine — must be excluded
        s.commit()

        blocks = list_recent_blocks(s, "m1")
        assert [b.machine_id for b in blocks] == ["m1", "m1"]
        # newest first: the fail_open (1h ago) before the deny (2h ago)
        assert blocks[0].fail_open is True
        assert blocks[1].rule_id == "hard.fs_wipe"


def test_list_recent_blocks_filters_by_age_and_limit() -> None:
    eng = _engine()
    now = datetime.now(UTC)
    with Session(eng) as s:
        s.add(_rec("m1", rule_id="hard.cred_exfil", reason="old", fail_open=False,
                   when=now - timedelta(days=30), fp="old"))  # outside 7d window
        s.add(_rec("m1", rule_id="hard.disable_security", reason="fresh", fail_open=False,
                   when=now - timedelta(hours=1), fp="fresh"))
        s.commit()

        blocks = list_recent_blocks(s, "m1", days=7)
        assert len(blocks) == 1
        assert blocks[0].reason == "fresh"

        capped = list_recent_blocks(s, "m1", days=7, limit=0)
        assert capped == []


def test_list_recent_blocks_empty_when_none() -> None:
    eng = _engine()
    with Session(eng) as s:
        assert list_recent_blocks(s, "m1") == []
