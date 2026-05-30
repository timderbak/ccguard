"""Agent-side: hook captures shell user defensively."""
from __future__ import annotations

import pytest

from ccguard.agent.audit_hook.actor import detect_actor_user


def test_returns_user_env_when_set(monkeypatch):
    monkeypatch.setenv("USER", "alice")
    assert detect_actor_user() == "alice"


def test_returns_logname_fallback(monkeypatch):
    monkeypatch.delenv("USER", raising=False)
    monkeypatch.setenv("LOGNAME", "bob")
    assert detect_actor_user() == "bob"


def test_returns_username_on_windows_fallback(monkeypatch):
    monkeypatch.delenv("USER", raising=False)
    monkeypatch.delenv("LOGNAME", raising=False)
    monkeypatch.setenv("USERNAME", "charlie")
    assert detect_actor_user() == "charlie"


def test_returns_none_when_no_env_and_oslogin_fails(monkeypatch):
    monkeypatch.delenv("USER", raising=False)
    monkeypatch.delenv("LOGNAME", raising=False)
    monkeypatch.delenv("USERNAME", raising=False)

    def _boom():
        raise OSError("no controlling terminal")

    monkeypatch.setattr("os.getlogin", _boom)
    assert detect_actor_user() is None


def test_caps_length_to_64(monkeypatch):
    monkeypatch.setenv("USER", "a" * 500)
    assert detect_actor_user() == "a" * 64


def test_strips_whitespace(monkeypatch):
    monkeypatch.setenv("USER", "  alice  ")
    assert detect_actor_user() == "alice"


def test_empty_string_treated_as_none(monkeypatch):
    monkeypatch.setenv("USER", "   ")
    monkeypatch.delenv("LOGNAME", raising=False)
    monkeypatch.delenv("USERNAME", raising=False)
    monkeypatch.setattr("os.getlogin", lambda: "")
    assert detect_actor_user() is None
