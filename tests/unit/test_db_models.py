"""Unit tests for AgentToken and WebSession SQLModel tables."""
from __future__ import annotations

from datetime import UTC, datetime, timedelta

from sqlmodel import Session, select

from ccguard.server.db.models import (
    AgentToken,
    AuditRecord,
    PolicyVersion,
    ToolUseEvent,
    WebSession,
)
from ccguard.server.db.session import init_db, make_engine


def _engine():
    eng = make_engine("sqlite://")
    init_db(eng)
    return eng


def test_agent_token_roundtrip() -> None:
    engine = _engine()
    with Session(engine) as s:
        s.add(AgentToken(label="agent-a", token_hash="hash-a"))
        s.commit()
    with Session(engine) as s:
        row = s.exec(select(AgentToken).where(AgentToken.label == "agent-a")).one()
        assert row.token_hash == "hash-a"
        assert row.id is not None
        assert row.created_at is not None
        assert row.last_used_at is None
        assert row.revoked_at is None


def test_web_session_roundtrip() -> None:
    engine = _engine()
    now = datetime.now(UTC)
    with Session(engine) as s:
        s.add(
            WebSession(
                id="sid-123",
                user_id="admin",
                created_at=now,
                expires_at=now + timedelta(hours=1),
            )
        )
        s.commit()
    with Session(engine) as s:
        row = s.get(WebSession, "sid-123")
        assert row is not None
        assert row.user_id == "admin"
        assert row.expires_at > row.created_at


def test_policy_version_roundtrip() -> None:
    engine = _engine()
    now = datetime.now(UTC)
    with Session(engine) as s:
        s.add(
            PolicyVersion(
                revision=1,
                status="published",
                yaml_text="meta:\n  schema_version: 1\n",
                comment="initial",
                created_by="admin",
                published_at=now,
            )
        )
        s.commit()
    with Session(engine) as s:
        row = s.exec(
            select(PolicyVersion).where(PolicyVersion.revision == 1)
        ).one()
        assert row.status == "published"
        assert row.created_by == "admin"
        assert row.published_at is not None
        assert "schema_version" in row.yaml_text


def test_tool_use_event_roundtrip() -> None:
    """TUA-02: ToolUseEvent persists and round-trips ts as UTC datetime."""
    engine = _engine()
    ts = datetime.now(UTC)
    with Session(engine) as s:
        s.add(
            ToolUseEvent(
                machine_id="laptop-1",
                ts=ts,
                tool_name="Bash",
                fingerprint="0123456789abcdef",
                decision="allow",
                result_status="success",
            )
        )
        s.commit()
    with Session(engine) as s:
        row = s.exec(select(ToolUseEvent)).one()
        assert row.machine_id == "laptop-1"
        assert row.tool_name == "Bash"
        assert row.fingerprint == "0123456789abcdef"
        assert row.decision == "allow"
        assert row.result_status == "success"
        # received_at is server-stamped (default_factory)
        assert row.received_at is not None
        # ts round-trip — value equal even if tz info is stripped by SQLite.
        # Compare on UTC-naive component.
        assert row.ts.replace(tzinfo=None) == ts.replace(tzinfo=None)


def test_audit_record_unchanged_by_tool_use_event_writes() -> None:
    """Semantic split regression: writing ToolUseEvent rows must NOT affect AuditRecord."""
    engine = _engine()
    with Session(engine) as s:
        before = len(list(s.exec(select(AuditRecord))))
        s.add(
            ToolUseEvent(
                machine_id="m",
                ts=datetime.now(UTC),
                tool_name="Bash",
                fingerprint="abcdef0123456789",
                decision="deny",
                result_status="blocked",
            )
        )
        s.commit()
        after = len(list(s.exec(select(AuditRecord))))
    assert before == after == 0
