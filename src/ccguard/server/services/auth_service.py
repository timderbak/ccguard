"""Authentication primitives: password hashing, web sessions."""
from __future__ import annotations

import secrets
from datetime import UTC, datetime, timedelta

import bcrypt
from sqlmodel import Session

from ccguard.server.db.models import WebSession


def _to_bytes(value: str) -> bytes:
    # bcrypt has a 72-byte limit; truncate consistently for hash + verify.
    return value.encode("utf-8")[:72]


def hash_password(plain: str) -> str:
    return bcrypt.hashpw(_to_bytes(plain), bcrypt.gensalt()).decode("utf-8")


def verify_password(plain: str, hashed: str) -> bool:
    try:
        return bcrypt.checkpw(_to_bytes(plain), hashed.encode("utf-8"))
    except (ValueError, TypeError):
        return False


def create_session(session: Session, user_id: str, ttl_hours: int = 24) -> str:
    sid = secrets.token_hex(32)
    now = datetime.now(UTC)
    session.add(
        WebSession(
            id=sid,
            user_id=user_id,
            created_at=now,
            expires_at=now + timedelta(hours=ttl_hours),
        )
    )
    session.commit()
    return sid


def session_is_valid(session: Session, sid: str) -> bool:
    row = session.get(WebSession, sid)
    if row is None:
        return False
    expires_at = row.expires_at
    if expires_at.tzinfo is None:
        expires_at = expires_at.replace(tzinfo=UTC)
    return expires_at > datetime.now(UTC)


def delete_session(session: Session, sid: str) -> None:
    row = session.get(WebSession, sid)
    if row is not None:
        session.delete(row)
        session.commit()
