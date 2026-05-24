"""Unit tests for CSRF token primitives."""
from __future__ import annotations

from ccguard.server.web.csrf import generate_csrf_token, verify_csrf_token


def test_same_session_verify() -> None:
    tok = generate_csrf_token(secret="s1", session_id="sid-abc")
    assert verify_csrf_token(tok, secret="s1", session_id="sid-abc") is True


def test_other_session_reject() -> None:
    tok = generate_csrf_token(secret="s1", session_id="sid-abc")
    assert verify_csrf_token(tok, secret="s1", session_id="sid-other") is False


def test_wrong_secret_reject() -> None:
    tok = generate_csrf_token(secret="s1", session_id="sid-abc")
    assert verify_csrf_token(tok, secret="s2", session_id="sid-abc") is False


def test_malformed_reject() -> None:
    assert verify_csrf_token("garbage", secret="s1", session_id="sid-abc") is False
    assert verify_csrf_token("", secret="s1", session_id="sid-abc") is False
