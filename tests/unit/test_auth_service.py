"""Unit tests for auth_service: password hashing and session lifecycle."""
from __future__ import annotations

from datetime import UTC, datetime, timedelta

from sqlmodel import Session

from ccguard.server.db.models import WebSession
from ccguard.server.db.session import init_db, make_engine
from ccguard.server.services.auth_service import (
    create_session,
    delete_session,
    hash_password,
    session_is_valid,
    verify_password,
)


def _engine():
    eng = make_engine("sqlite://")
    init_db(eng)
    return eng


def test_hash_then_verify_roundtrip() -> None:
    h = hash_password("hunter2")
    assert h != "hunter2"
    assert verify_password("hunter2", h) is True
    assert verify_password("wrong", h) is False
    assert verify_password("hunter2", "not-a-hash") is False


def test_create_session_persists_row() -> None:
    engine = _engine()
    with Session(engine) as s:
        sid = create_session(s, user_id="admin", ttl_hours=24)
        assert len(sid) >= 32
        row = s.get(WebSession, sid)
        assert row is not None
        assert row.user_id == "admin"
        # SQLite roundtrip may strip tz; compare naive-to-naive.
        expires = row.expires_at
        if expires.tzinfo is None:
            assert expires > datetime.now(UTC).replace(tzinfo=None)
        else:
            assert expires > datetime.now(UTC)


def test_session_is_valid_expiry() -> None:
    engine = _engine()
    now = datetime.now(UTC)
    with Session(engine) as s:
        # past
        s.add(WebSession(id="past", user_id="u", created_at=now - timedelta(hours=2), expires_at=now - timedelta(hours=1)))
        # future
        s.add(WebSession(id="future", user_id="u", created_at=now, expires_at=now + timedelta(hours=1)))
        s.commit()
        assert session_is_valid(s, "past") is False
        assert session_is_valid(s, "future") is True
        assert session_is_valid(s, "nonexistent") is False


def test_delete_session_removes_row() -> None:
    engine = _engine()
    with Session(engine) as s:
        sid = create_session(s, user_id="admin")
        delete_session(s, sid)
        assert s.get(WebSession, sid) is None
        # nonexistent — no error
        delete_session(s, "nope")
