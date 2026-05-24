"""Unit tests for AgentToken and WebSession SQLModel tables."""
from __future__ import annotations

from datetime import UTC, datetime, timedelta

from sqlmodel import Session, select

from ccguard.server.db.models import AgentToken, WebSession
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
