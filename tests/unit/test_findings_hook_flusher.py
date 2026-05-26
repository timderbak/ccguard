"""Unit tests for ccguard.agent.findings_hook.flusher (PI-01, T-05-04-03..04).

Clone-not-extend test scaffold mirroring tests.unit.test_audit_flusher: drain
loop, batching, retry+backoff, DLQ-style guard on persistent 4xx, and
X-CCGuard-Token header injection.
"""

from __future__ import annotations

import sqlite3
import time
from pathlib import Path
from types import SimpleNamespace

import httpx
import pytest


@pytest.fixture(autouse=True)
def _isolated_home(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    cc_home = tmp_path / ".ccguard"
    cc_home.mkdir()
    monkeypatch.setenv("CCGUARD_AGENT_HOME", str(cc_home))
    monkeypatch.setenv("HOME", str(tmp_path))
    return cc_home


@pytest.fixture(autouse=True)
def _reset_buffer_module() -> None:
    from ccguard.agent.findings_hook import buffer as buf_mod

    buf_mod._reset_for_tests()
    yield
    buf_mod._reset_for_tests()


def _seed(home: Path, n: int) -> None:
    from ccguard.agent.findings_hook.buffer import emit_finding

    for i in range(n):
        emit_finding(
            rule_id="prompt_injection.role_swap",
            severity="warn",
            title=f"finding-{i}",
            source="regex",
            matched_pattern=f"value-{i}",
            tool_name="Bash",
        )


def _patch_config_and_machine(monkeypatch: pytest.MonkeyPatch) -> None:
    cfg = SimpleNamespace(
        server=SimpleNamespace(url="http://test", token="tok"),
        install_salt="salty",
    )
    monkeypatch.setattr(
        "ccguard.agent.config.load_or_create",
        lambda *_a, **_k: (cfg, Path("/tmp/nope")),
    )
    monkeypatch.setattr(
        "ccguard.agent.machine_id.derive_machine_id",
        lambda *_a, **_k: "machine-test",
    )


def _count(home: Path, *, delivered: int | None = None) -> int:
    db = home / "findings_buffer.db"
    if not db.exists():
        return 0
    conn = sqlite3.connect(str(db))
    try:
        if delivered is None:
            q = "SELECT COUNT(*) FROM findings_buffer"
            return int(conn.execute(q).fetchone()[0])
        return int(
            conn.execute(
                "SELECT COUNT(*) FROM findings_buffer WHERE delivered = ?",
                (delivered,),
            ).fetchone()[0]
        )
    finally:
        conn.close()


def _max_retry(home: Path) -> int:
    conn = sqlite3.connect(str(home / "findings_buffer.db"))
    try:
        r = conn.execute("SELECT COALESCE(MAX(retry_count), 0) FROM findings_buffer").fetchone()
        return int(r[0])
    finally:
        conn.close()


class _MockClient:
    """Configurable mock for ``httpx.Client(...)`` context-manager usage."""

    def __init__(self, status: int = 200, exc: type[BaseException] | None = None) -> None:
        self.status = status
        self.exc = exc
        self.calls: list[dict] = []

    def __call__(self, *a: object, **k: object) -> _MockClient:
        return self

    def __enter__(self) -> _MockClient:
        return self

    def __exit__(self, *a: object) -> None:
        return None

    def post(self, url: str, *, content: bytes | str, headers: dict) -> httpx.Response:
        self.calls.append({"url": url, "content": content, "headers": headers})
        if self.exc is not None:
            raise self.exc("boom")
        req = httpx.Request("POST", url)
        return httpx.Response(self.status, request=req, json={"accepted": True})


# --- Test 1: success drains and marks delivered ------------------------------


def test_flush_success_marks_delivered(
    _isolated_home: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _seed(_isolated_home, n=3)
    _patch_config_and_machine(monkeypatch)
    mock = _MockClient(status=200)
    monkeypatch.setattr(httpx, "Client", mock)

    # Avoid sleeping in retry tests.
    monkeypatch.setattr(time, "sleep", lambda _s: None)

    from ccguard.agent.findings_hook.flusher import flush

    flush()

    assert _count(_isolated_home, delivered=1) == 3
    assert _count(_isolated_home, delivered=0) == 0
    assert len(mock.calls) == 1
    assert mock.calls[0]["url"] == "http://test/api/v1/findings"


# --- Test 2: network error → retry_count++, delivered stays 0 ----------------


def test_flush_network_error_increments_retry(
    _isolated_home: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _seed(_isolated_home, n=2)
    _patch_config_and_machine(monkeypatch)
    monkeypatch.setattr(time, "sleep", lambda _s: None)
    mock = _MockClient(exc=httpx.ConnectError)
    monkeypatch.setattr(httpx, "Client", mock)

    from ccguard.agent.findings_hook.flusher import flush

    flush()

    # All rows still undelivered; retry_count incremented at least once.
    assert _count(_isolated_home, delivered=0) == 2
    assert _max_retry(_isolated_home) >= 1


# --- Test 3: server 5xx → retry_count++, delivered stays 0 -------------------


def test_flush_server_5xx_increments_retry(
    _isolated_home: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _seed(_isolated_home, n=2)
    _patch_config_and_machine(monkeypatch)
    monkeypatch.setattr(time, "sleep", lambda _s: None)
    mock = _MockClient(status=503)
    monkeypatch.setattr(httpx, "Client", mock)

    from ccguard.agent.findings_hook.flusher import flush

    flush()

    assert _count(_isolated_home, delivered=0) == 2
    assert _max_retry(_isolated_home) >= 1


# --- Test 4: persistent 4xx → DLQ-style mark delivered after retry_count>=3 --


def test_flush_dlq_marks_delivered_after_three_retries(
    _isolated_home: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _seed(_isolated_home, n=1)
    _patch_config_and_machine(monkeypatch)
    monkeypatch.setattr(time, "sleep", lambda _s: None)
    mock = _MockClient(status=400)
    monkeypatch.setattr(httpx, "Client", mock)

    from ccguard.agent.findings_hook.flusher import flush

    # Call flush() repeatedly — each invocation increments retry_count by 1
    # for rows it tried to deliver. After 3 attempts the row gets a DLQ-style
    # delivered=1 mark to break the loop.
    flush()
    flush()
    flush()

    # After 3 failed flush() rounds, retry_count >= 3 → mark delivered=1.
    assert _count(_isolated_home, delivered=1) == 1
    assert _count(_isolated_home, delivered=0) == 0


# --- Test 5: empty buffer is a no-op -----------------------------------------


def test_flush_empty_buffer_noop(
    _isolated_home: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # Don't seed; just initialize the schema by hitting emit_finding once and
    # then marking that single row delivered manually so the next flush is a
    # true empty-undelivered scenario.
    _seed(_isolated_home, n=1)
    db = _isolated_home / "findings_buffer.db"
    conn = sqlite3.connect(str(db))
    try:
        conn.execute("UPDATE findings_buffer SET delivered = 1")
        conn.commit()
    finally:
        conn.close()

    _patch_config_and_machine(monkeypatch)
    mock = _MockClient(status=200)
    monkeypatch.setattr(httpx, "Client", mock)

    from ccguard.agent.findings_hook.flusher import flush

    flush()

    # No POST should have been made.
    assert mock.calls == []


# --- Test 6: batching — flush all even when > batch size ---------------------


def test_flush_batches_large_buffer(
    _isolated_home: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    n = 250  # > _BATCH_SIZE=100
    _seed(_isolated_home, n=n)
    _patch_config_and_machine(monkeypatch)
    monkeypatch.setattr(time, "sleep", lambda _s: None)
    mock = _MockClient(status=200)
    monkeypatch.setattr(httpx, "Client", mock)

    from ccguard.agent.findings_hook.flusher import flush

    flush()

    # Multiple POSTs each <= 100 records; all rows marked delivered.
    assert _count(_isolated_home, delivered=1) == n
    assert _count(_isolated_home, delivered=0) == 0
    assert len(mock.calls) >= 3
    # Verify no single batch exceeded 100 entries.
    import json as _json

    for call in mock.calls:
        body = _json.loads(call["content"])
        # Envelope shape: {schema_version, machine_id, findings: [...]}.
        # Findings list inside each request must respect _BATCH_SIZE=100.
        assert isinstance(body, dict)
        assert "findings" in body
        assert len(body["findings"]) <= 100


# --- Test 7: flusher_main entrypoint exits 0 (oneshot) -----------------------


def test_flusher_main_oneshot_runs_and_exits(
    _isolated_home: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _patch_config_and_machine(monkeypatch)
    monkeypatch.setattr(time, "sleep", lambda _s: None)
    mock = _MockClient(status=200)
    monkeypatch.setattr(httpx, "Client", mock)

    from ccguard.agent.findings_hook import flusher_main

    rc = flusher_main.main()
    assert rc == 0


# --- Test 8: X-CCGuard-Token header present ---------------------------------


def test_flush_includes_token_header(
    _isolated_home: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _seed(_isolated_home, n=1)
    _patch_config_and_machine(monkeypatch)
    monkeypatch.setattr(time, "sleep", lambda _s: None)
    mock = _MockClient(status=200)
    monkeypatch.setattr(httpx, "Client", mock)

    from ccguard.agent.findings_hook.flusher import flush

    flush()

    assert mock.calls[0]["headers"]["X-CCGuard-Token"] == "tok"


# --- Test 9: TestClient integration — server stores in FindingRecord --------
# Integration-style: uses the same TestClient fixture wiring as audit tests.


def test_server_findings_endpoint_accepts_batch(
    _isolated_home: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Round-trip: agent payload → server router → FindingRecord row.

    Mirrors the audit integration ``client`` fixture but inlined here so the
    test stays in the unit suite (no need for a separate integration file —
    Phase 5 plan 04 owns this server endpoint extension).
    """
    from fastapi.testclient import TestClient
    from sqlmodel import Session, select

    from ccguard.server.config import ServerConfig, TokenEntry
    from ccguard.server.db.models import FindingRecord
    from ccguard.server.db.session import init_db, make_engine
    from ccguard.server.main import create_app
    from ccguard.server.policy_loader import PolicyLoader

    tmp_root = _isolated_home.parent  # the per-test tmp_path
    policy_yaml = tmp_root / "policy.yaml"
    policy_yaml.write_text(
        "meta:\n  revision: 1\n  updated_at: 2026-05-25T00:00:00Z\n"
    )
    db_path = tmp_root / "server.db"
    cfg = ServerConfig(
        tokens=[TokenEntry(value="test-tok", label="t")],
        policy_path=str(policy_yaml),
        db_url=f"sqlite:///{db_path}",
    )
    app = create_app()
    engine = make_engine(cfg.db_url)
    init_db(engine)
    app.state.config = cfg
    app.state.engine = engine
    app.state.policy_loader = PolicyLoader(file_path=policy_yaml, engine=engine)

    payload = {
        "schema_version": "1",
        "machine_id": "machine-test",
        "findings": [
            {
                "ts": "2026-05-25T12:00:00+00:00",
                "rule_id": "prompt_injection.role_swap",
                "severity": "warn",
                "title": "role-swap pattern matched",
                "source": "regex",
                "matched_pattern": "act as admin",
                "tool_name": "Bash",
            }
        ],
    }
    with TestClient(app) as c:
        c.app.state.config = cfg  # type: ignore[attr-defined]
        c.app.state.engine = engine  # type: ignore[attr-defined]
        c.app.state.policy_loader = PolicyLoader(file_path=policy_yaml, engine=engine)  # type: ignore[attr-defined]
        r = c.post(
            "/api/v1/findings",
            json=payload,
            headers={"X-CCGuard-Token": "test-tok"},
        )
        assert r.status_code in (200, 201), r.text
        body = r.json()
        assert body.get("accepted") == 1 or body.get("stored") == 1

        with Session(engine) as s:
            rows = list(s.exec(select(FindingRecord)))
            assert len(rows) == 1
            row = rows[0]
            assert row.machine_id == "machine-test"
            assert row.rule_id == "prompt_injection.role_swap"
            assert row.severity == "warn"
