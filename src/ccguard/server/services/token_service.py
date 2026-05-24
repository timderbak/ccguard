"""Agent token CRUD: create / list / revoke / validate."""
from __future__ import annotations

import hashlib
import secrets
from datetime import UTC, datetime

from sqlmodel import Session, select

from ccguard.server.db.models import AgentToken


def _hash(raw: str) -> str:
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


def create_token(session: Session, *, label: str) -> str:
    raw = secrets.token_urlsafe(32)
    row = AgentToken(label=label, token_hash=_hash(raw))
    session.add(row)
    session.commit()
    return raw


def list_tokens(session: Session) -> list[AgentToken]:
    rows = session.exec(
        select(AgentToken).where(AgentToken.revoked_at.is_(None))
    ).all()
    return list(rows)


def revoke_token(session: Session, token_id: int) -> None:
    row = session.get(AgentToken, token_id)
    if row is None:
        return
    row.revoked_at = datetime.now(UTC)
    session.add(row)
    session.commit()


def bootstrap_env_tokens(session: Session, *, env_tokens: list[str]) -> None:
    """Migrate env-configured tokens into AgentToken if the table is empty."""
    existing = session.exec(select(AgentToken).limit(1)).first()
    if existing is not None:
        return
    for i, raw in enumerate(env_tokens):
        if not raw:
            continue
        session.add(AgentToken(label=f"env-bootstrap-{i}", token_hash=_hash(raw)))
    session.commit()


def is_token_valid(session: Session, raw: str) -> bool:
    row = session.exec(
        select(AgentToken).where(
            AgentToken.token_hash == _hash(raw),
            AgentToken.revoked_at.is_(None),
        )
    ).first()
    if row is None:
        return False
    row.last_used_at = datetime.now(UTC)
    session.add(row)
    session.commit()
    return True
