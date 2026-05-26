"""Phase 5 / 05-05 Task 2: tests for _parse_prompt_injection and POST /policy/draft validation.

Covers:
- Happy-path parsing → 303 redirect, prompt_injection persisted in YAML
- Empty-state defaults (checkbox missing = unchecked, empty textarea → [])
- Invalid regex (re.error) → re-render 200 with Russian error notice
- ReDoS probe rejects pathological backtracking patterns
- Bad LlamaGuard endpoint URL (only when LG enabled)
- Timeout out of range
- Bad severity enum value
- Backward-compat: missing prompt_injection.* fields → defaults applied
"""

from __future__ import annotations

import pytest
import yaml
from fastapi.testclient import TestClient
from sqlmodel import Session, select

from ccguard.server.db.models import PolicyVersion
from ccguard.server.main import create_app
from ccguard.server.services.auth_service import create_session, hash_password
from ccguard.server.web.csrf import generate_csrf_token


_BASE_YAML = (
    "meta:\n  schema_version: 1\n  revision: 1\n  updated_at: '2026-01-01T00:00:00Z'\n"
)


# Minimal field set for the 7 existing rule sections so form_to_yaml validates.
_RULES_MIN: dict[str, str] = {
    "mcp_servers.severity": "warn",
    "network.severity": "warn",
    "commands.severity": "warn",
    "skills.severity": "warn",
    "hooks.severity": "warn",
    "agents.severity": "warn",
    "env.severity": "warn",
}


def _form_with_pi(csrf: str, **pi_overrides: str) -> dict[str, str]:
    """Build a complete form with default PI fields + overrides."""
    base: dict[str, str] = {
        "csrf_token": csrf,
        "tab": "rules",
        **_RULES_MIN,
        "prompt_injection.enabled": "1",
        "prompt_injection.severity": "warn",
        "prompt_injection.regex_patterns": "",
        "prompt_injection.allowlist_patterns": "",
        "prompt_injection.llama_guard.enabled": "",
        "prompt_injection.llama_guard.endpoint": "http://localhost:11434",
        "prompt_injection.llama_guard.timeout_ms": "150",
    }
    # Allow caller to remove a key by passing the empty sentinel via __delete__.
    for k, v in pi_overrides.items():
        # Translate underscored kwarg back to dotted form field name.
        form_key = k.replace("__", ".")
        base[form_key] = v
    return base


@pytest.fixture
def client_session(monkeypatch, tmp_path):
    monkeypatch.setenv("CCGUARD_ADMIN_PASSWORD_HASH", hash_password("h"))
    monkeypatch.setenv("CCGUARD_DB_URL", f"sqlite:///{tmp_path}/web.db")
    monkeypatch.setenv("CCGUARD_SESSION_SECRET", "s")
    monkeypatch.setenv("CCGUARD_TOKENS", "test-tok")

    with TestClient(create_app()) as client:
        engine = client.app.state.engine
        with Session(engine) as s:
            s.add(
                PolicyVersion(
                    revision=1,
                    status="published",
                    yaml_text=_BASE_YAML,
                    created_by="admin",
                )
            )
            sid = create_session(s, user_id="admin")
        csrf = generate_csrf_token(secret="s", session_id=sid)
        yield client, sid, csrf, engine


def _latest_draft_yaml(engine) -> dict:
    with Session(engine) as s:
        rows = s.exec(
            select(PolicyVersion).where(PolicyVersion.status == "draft")
        ).all()
        assert rows, "no draft saved"
        # Last by revision
        rows.sort(key=lambda r: r.revision)
        return yaml.safe_load(rows[-1].yaml_text)


# --- Happy path -----------------------------------------------------------


def test_parse_happy_path_persists_pi(client_session):
    client, sid, csrf, engine = client_session
    form = _form_with_pi(
        csrf,
        prompt_injection__severity="block",
        prompt_injection__regex_patterns="foo\nbar",
        prompt_injection__llama_guard__enabled="1",
    )
    r = client.post(
        "/policy/draft",
        data=form,
        cookies={"ccg_session": sid},
        follow_redirects=False,
    )
    assert r.status_code == 303, r.text[:400]
    data = _latest_draft_yaml(engine)
    pi = data["prompt_injection"]
    assert pi["enabled"] is True
    assert pi["severity"] == "block"
    assert pi["regex_patterns"] == ["foo", "bar"]
    assert pi["llama_guard"]["enabled"] is True
    assert pi["llama_guard"]["endpoint"] == "http://localhost:11434"
    assert pi["llama_guard"]["timeout_ms"] == 150


def test_checkbox_missing_means_unchecked(client_session):
    client, sid, csrf, engine = client_session
    form = _form_with_pi(csrf)
    # Remove the enabled key entirely — HTML checkbox semantics
    form.pop("prompt_injection.enabled")
    r = client.post(
        "/policy/draft",
        data=form,
        cookies={"ccg_session": sid},
        follow_redirects=False,
    )
    assert r.status_code == 303
    data = _latest_draft_yaml(engine)
    assert data["prompt_injection"]["enabled"] is False


def test_empty_textarea_yields_empty_list(client_session):
    client, sid, csrf, engine = client_session
    form = _form_with_pi(
        csrf,
        prompt_injection__regex_patterns="  \n\n   \n",  # whitespace-only lines
        prompt_injection__allowlist_patterns="",
    )
    r = client.post(
        "/policy/draft",
        data=form,
        cookies={"ccg_session": sid},
        follow_redirects=False,
    )
    assert r.status_code == 303
    data = _latest_draft_yaml(engine)
    assert data["prompt_injection"]["regex_patterns"] == []
    assert data["prompt_injection"]["allowlist_patterns"] == []


# --- Invalid regex --------------------------------------------------------


def test_invalid_regex_renders_error(client_session):
    client, sid, csrf, _engine = client_session
    form = _form_with_pi(
        csrf,
        prompt_injection__regex_patterns="valid_pattern\n(.*)+\nanother",
    )
    r = client.post(
        "/policy/draft",
        data=form,
        cookies={"ccg_session": sid},
        follow_redirects=False,
    )
    assert r.status_code == 200, f"expected re-render, got {r.status_code}"
    assert (
        "Невалидный regex в строке 2: «(.*)+». Исправьте и сохраните снова."
        in r.text
    )
    # User input preserved
    assert "valid_pattern" in r.text
    assert "(.*)+" in r.text
    assert "another" in r.text


def test_invalid_regex_in_allowlist(client_session):
    client, sid, csrf, _engine = client_session
    form = _form_with_pi(
        csrf,
        prompt_injection__allowlist_patterns="re:bad(((",
    )
    r = client.post(
        "/policy/draft",
        data=form,
        cookies={"ccg_session": sid},
        follow_redirects=False,
    )
    assert r.status_code == 200
    assert "Невалидный regex в allowlist, строка 1: «re:bad(((»." in r.text


def test_redos_probe_rejects_pathological_pattern(client_session):
    client, sid, csrf, _engine = client_session
    # Catastrophic backtracking pattern: compiles fine but slow on 'a'*1000
    form = _form_with_pi(
        csrf,
        prompt_injection__regex_patterns=r"^(a+)+$",
    )
    r = client.post(
        "/policy/draft",
        data=form,
        cookies={"ccg_session": sid},
        follow_redirects=False,
    )
    assert r.status_code == 200, f"expected re-render due to ReDoS probe, got {r.status_code}"
    assert "Невалидный regex в строке 1:" in r.text


# --- LlamaGuard validation -----------------------------------------------


def test_bad_endpoint_when_lg_enabled(client_session):
    client, sid, csrf, _engine = client_session
    form = _form_with_pi(
        csrf,
        prompt_injection__llama_guard__enabled="1",
        prompt_injection__llama_guard__endpoint="not-a-url",
    )
    r = client.post(
        "/policy/draft",
        data=form,
        cookies={"ccg_session": sid},
        follow_redirects=False,
    )
    assert r.status_code == 200
    assert (
        "Endpoint LlamaGuard должен быть валидным URL (http:// или https://)."
        in r.text
    )


def test_bad_endpoint_ignored_when_lg_disabled(client_session):
    client, sid, csrf, engine = client_session
    form = _form_with_pi(
        csrf,
        prompt_injection__llama_guard__enabled="",  # disabled
        prompt_injection__llama_guard__endpoint="not-a-url",
    )
    r = client.post(
        "/policy/draft",
        data=form,
        cookies={"ccg_session": sid},
        follow_redirects=False,
    )
    # LG disabled → endpoint validation skipped per UI-SPEC
    assert r.status_code == 303, r.text[:400]


def test_bad_timeout_low(client_session):
    client, sid, csrf, _engine = client_session
    form = _form_with_pi(csrf, prompt_injection__llama_guard__timeout_ms="49")
    r = client.post(
        "/policy/draft",
        data=form,
        cookies={"ccg_session": sid},
        follow_redirects=False,
    )
    assert r.status_code == 200
    assert "timeout_ms должен быть в диапазоне 50–200 мс." in r.text


def test_bad_timeout_high(client_session):
    client, sid, csrf, _engine = client_session
    # CR-04: upper bound clamped 10000→200 so PreToolUse hook stays inside SLA.
    form = _form_with_pi(csrf, prompt_injection__llama_guard__timeout_ms="201")
    r = client.post(
        "/policy/draft",
        data=form,
        cookies={"ccg_session": sid},
        follow_redirects=False,
    )
    assert r.status_code == 200
    assert "timeout_ms должен быть в диапазоне 50–200 мс." in r.text


def test_bad_timeout_non_int(client_session):
    client, sid, csrf, _engine = client_session
    form = _form_with_pi(csrf, prompt_injection__llama_guard__timeout_ms="abc")
    r = client.post(
        "/policy/draft",
        data=form,
        cookies={"ccg_session": sid},
        follow_redirects=False,
    )
    assert r.status_code == 200
    assert "timeout_ms должен быть в диапазоне 50–200 мс." in r.text


def test_bad_severity(client_session):
    client, sid, csrf, _engine = client_session
    form = _form_with_pi(csrf, prompt_injection__severity="bogus")
    r = client.post(
        "/policy/draft",
        data=form,
        cookies={"ccg_session": sid},
        follow_redirects=False,
    )
    assert r.status_code == 200
    assert "severity должен быть одним из: info, warn, block." in r.text


# --- Backward compat ------------------------------------------------------


def test_backward_compat_missing_pi_fields(client_session):
    """Form without any prompt_injection.* keys still parses and applies defaults."""
    client, sid, csrf, engine = client_session
    form: dict[str, str] = {"csrf_token": csrf, "tab": "rules", **_RULES_MIN}
    r = client.post(
        "/policy/draft",
        data=form,
        cookies={"ccg_session": sid},
        follow_redirects=False,
    )
    assert r.status_code == 303, r.text[:400]
    data = _latest_draft_yaml(engine)
    pi = data["prompt_injection"]
    # enabled=False because checkbox missing per HTML semantics
    assert pi["enabled"] is False
    assert pi["severity"] == "warn"
    assert pi["regex_patterns"] == []
    assert pi["allowlist_patterns"] == []
    assert pi["llama_guard"]["enabled"] is False
    assert pi["llama_guard"]["endpoint"] == "http://localhost:11434"
    assert pi["llama_guard"]["timeout_ms"] == 150


def test_existing_sections_not_broken(client_session):
    """A complete valid form publishes and existing 7 sections remain intact."""
    client, sid, csrf, engine = client_session
    form = _form_with_pi(
        csrf,
        prompt_injection__regex_patterns="(?i)ignore previous",
    )
    r = client.post(
        "/policy/draft",
        data=form,
        cookies={"ccg_session": sid},
        follow_redirects=False,
    )
    assert r.status_code == 303
    data = _latest_draft_yaml(engine)
    # All 7 existing sections still present with severity=warn
    for section in (
        "mcp_servers",
        "network",
        "commands",
        "skills",
        "hooks",
        "agents",
        "env",
    ):
        assert data[section]["severity"] == "warn"
