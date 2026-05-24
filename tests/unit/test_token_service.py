"""Unit tests for agent token CRUD service."""
from __future__ import annotations

import pytest
from sqlmodel import Session

from ccguard.server.db.session import init_db, make_engine
from ccguard.server.services import token_service


@pytest.fixture
def db():
    engine = make_engine("sqlite://")
    init_db(engine)
    with Session(engine) as s:
        yield s


def test_create_then_validate(db) -> None:
    raw = token_service.create_token(db, label="agent-a")
    assert isinstance(raw, str)
    assert len(raw) > 20
    assert token_service.is_token_valid(db, raw) is True


def test_invalid_token_rejected(db) -> None:
    token_service.create_token(db, label="agent-a")
    assert token_service.is_token_valid(db, "nope-not-a-real-token") is False


def test_revoked_token_invalid(db) -> None:
    raw = token_service.create_token(db, label="agent-a")
    rows = token_service.list_tokens(db)
    assert len(rows) == 1
    token_service.revoke_token(db, rows[0].id)
    assert token_service.is_token_valid(db, raw) is False
    assert token_service.list_tokens(db) == []


def test_list_tokens_excludes_hash(db) -> None:
    raw = token_service.create_token(db, label="agent-a")
    rows = token_service.list_tokens(db)
    # Raw token must not be stored verbatim — only sha256 hash.
    for row in rows:
        assert row.token_hash != raw
        assert len(row.token_hash) == 64  # sha256 hex
