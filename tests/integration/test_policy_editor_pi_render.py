"""Phase 5 / 05-05 Task 1: render tests for the new Prompt-Injection section card on /policy.

Verifies the 8th `<details>` card on the Правила tab — Russian copy verbatim per
05-UI-SPEC.md «Copywriting Contract», form-field naming convention, default
values render correctly, draft values pre-fill, ordering (after Env), and that
/policy/mandatory is NOT touched.
"""

from __future__ import annotations

import pytest
import yaml
from fastapi.testclient import TestClient
from sqlmodel import Session

from ccguard.server.db.models import PolicyVersion
from ccguard.server.main import create_app
from ccguard.server.services.auth_service import create_session, hash_password
from ccguard.server.web.csrf import generate_csrf_token


_BASE_YAML = (
    "meta:\n  schema_version: 1\n  revision: 1\n  updated_at: '2026-01-01T00:00:00Z'\n"
)


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


def test_card_heading_present(client_session):
    client, sid, _csrf, _engine = client_session
    r = client.get("/policy", cookies={"ccg_session": sid})
    assert r.status_code == 200
    # Heading copy must render inside a <summary> (styling/markup is not locked).
    import re as _re

    assert _re.search(r"<summary[^>]*>.*?Prompt-Injection", r.text, _re.S) is not None


def test_all_locked_russian_strings_present(client_session):
    client, sid, _csrf, _engine = client_session
    r = client.get("/policy", cookies={"ccg_session": sid})
    assert r.status_code == 200
    locked = [
        "Включить детекцию prompt-injection",
        "severity (действие при срабатывании)",
        "info — только в /findings",
        "warn — разрешить, но залогировать",
        "block — запретить вызов",
        "regex_patterns (по одному паттерну на строку, добавляются к встроенному набору)",
        "allowlist_patterns (по одному на строку; матч → finding не создаётся)",
        "LlamaGuard (опционально)",
        "Включить LlamaGuard (deep-scan через локальный Ollama)",
        "endpoint (URL Ollama API)",
        "timeout_ms (50–200; при таймауте — fail-open)",
        "Опционально — deep-scan через локальный Ollama. По умолчанию выключен. При недоступности — fail-open, tool-call разрешается.",
    ]
    for s in locked:
        assert s in r.text, f"missing locked copy: {s!r}"


def test_form_field_names(client_session):
    client, sid, _csrf, _engine = client_session
    r = client.get("/policy", cookies={"ccg_session": sid})
    for name in [
        'name="prompt_injection.enabled"',
        'name="prompt_injection.severity"',
        'name="prompt_injection.regex_patterns"',
        'name="prompt_injection.allowlist_patterns"',
        'name="prompt_injection.llama_guard.enabled"',
        'name="prompt_injection.llama_guard.endpoint"',
        'name="prompt_injection.llama_guard.timeout_ms"',
    ]:
        assert name in r.text, f"missing form field: {name}"


def test_defaults_rendered_no_draft(client_session):
    """No draft + baseline policy without explicit prompt_injection: Pydantic defaults render.

    Expected: enabled checked, severity=warn selected, LG endpoint=http://localhost:11434,
    LG timeout=150 (CR-04), empty-state helper for regex.
    """
    client, sid, _csrf, _engine = client_session
    r = client.get("/policy", cookies={"ccg_session": sid})
    # enabled default True per PromptInjectionConfig
    assert (
        'name="prompt_injection.enabled"' in r.text
        and 'checked' in r.text  # at least one checked (the enabled toggle)
    )
    # severity=warn selected
    assert "warn — разрешить, но залогировать</option>" in r.text
    # The warn option must have the selected attribute
    # Look for the warn <option> with `selected`
    import re as _re
    m = _re.search(
        r'<option value="warn"[^>]*selected[^>]*>warn — разрешить, но залогировать',
        r.text,
    )
    assert m is not None, "warn option should be selected by default"
    # LG endpoint default URL appears
    assert "http://localhost:11434" in r.text
    # LG timeout default 150 appears (as value="150") — CR-04
    assert 'value="150"' in r.text
    # Empty-state helper for regex_patterns
    assert "Пусто — используется встроенный набор паттернов." in r.text
    # Empty-state helper for allowlist
    assert "Пусто — allowlist отключён." in r.text


def test_draft_values_prefill(client_session):
    """With a draft containing prompt_injection patterns, textarea pre-fills and non-empty helper text shows."""
    client, sid, csrf, engine = client_session
    # Write a draft yaml that includes prompt_injection patterns.
    draft_yaml = yaml.safe_dump(
        {
            "meta": {
                "schema_version": 1,
                "revision": 2,
                "updated_at": "2026-01-02T00:00:00Z",
            },
            "prompt_injection": {
                "enabled": True,
                "severity": "block",
                "regex_patterns": ["foo_pat", "bar_pat"],
                "allowlist_patterns": ["allow1"],
                "llama_guard": {
                    "enabled": True,
                    "endpoint": "http://example.com:11434",
                    "timeout_ms": 175,
                },
            },
        },
        sort_keys=False,
    )
    with Session(engine) as s:
        s.add(
            PolicyVersion(
                revision=2,
                status="draft",
                yaml_text=draft_yaml,
                created_by="admin",
            )
        )
        s.commit()
    r = client.get("/policy", cookies={"ccg_session": sid})
    assert r.status_code == 200, r.text[:500]
    assert "foo_pat" in r.text
    assert "bar_pat" in r.text
    assert "allow1" in r.text
    assert "http://example.com:11434" in r.text
    assert 'value="175"' in r.text
    # block selected
    import re as _re
    m = _re.search(
        r'<option value="block"[^>]*selected[^>]*>block — запретить вызов',
        r.text,
    )
    assert m is not None, "block option should be selected when severity=block"
    # Non-empty helper text appears
    assert "Пользовательские паттерны добавляются к встроенному набору." in r.text
    assert "Проверяется до regex-детекции." in r.text


def test_card_appears_after_env_section(client_session):
    client, sid, _csrf, _engine = client_session
    r = client.get("/policy", cookies={"ccg_session": sid})
    # The env section has the form field "env.severity"; PI card must come after.
    env_idx = r.text.find('name="env.severity"')
    pi_idx = r.text.find("Prompt-Injection")
    assert env_idx > 0
    assert pi_idx > 0
    assert pi_idx > env_idx, "Prompt-Injection card must appear after Env section"


def test_card_not_on_mandatory_tab(client_session):
    client, sid, _csrf, _engine = client_session
    r = client.get("/policy/mandatory", cookies={"ccg_session": sid})
    assert r.status_code == 200
    assert "Prompt-Injection" not in r.text
    assert 'prompt_injection.enabled' not in r.text


def test_validation_error_notice_renders(client_session):
    """When errors.prompt_injection is present in context, the red notice renders inside the card."""
    client, sid, csrf, _engine = client_session
    # Submit a draft with an invalid regex to trigger the error path.
    bad_form = {
        "csrf_token": csrf,
        "tab": "rules",
        # Minimal fields for all 7 existing sections
        "mcp_servers.severity": "warn",
        "network.severity": "warn",
        "commands.severity": "warn",
        "skills.severity": "warn",
        "hooks.severity": "warn",
        "agents.severity": "warn",
        "env.severity": "warn",
        # Prompt-Injection — invalid regex on line 2
        "prompt_injection.enabled": "1",
        "prompt_injection.severity": "warn",
        "prompt_injection.regex_patterns": "valid_one\n(.*)+\nthird",
        "prompt_injection.allowlist_patterns": "",
        "prompt_injection.llama_guard.enabled": "",
        "prompt_injection.llama_guard.endpoint": "http://localhost:11434",
        "prompt_injection.llama_guard.timeout_ms": "150",
    }
    r = client.post(
        "/policy/draft",
        data=bad_form,
        cookies={"ccg_session": sid},
        follow_redirects=False,
    )
    # Re-render (NOT 303); error notice visible
    assert r.status_code == 200, f"expected 200 re-render, got {r.status_code}: {r.text[:400]}"
    assert "Невалидный regex в строке 2: «(.*)+». Исправьте и сохраните снова." in r.text
    # red error class present
    assert 'text-red-600' in r.text
    # User input preserved in textarea: all three lines including the bad one
    assert "valid_one" in r.text
    assert "(.*)+" in r.text
    assert "third" in r.text
