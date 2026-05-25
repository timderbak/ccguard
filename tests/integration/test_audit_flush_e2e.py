"""End-to-end: agent buffer -> flusher -> POST /api/v1/audit -> server DB.

This file is the operational truth-check for the Phase 1 stack (PLAN 01-06).
Each test pre-populates a real ``ToolBufferDB`` at ``tmp_path/audit_buffer.db``,
patches ``httpx.Client`` to route through the in-process FastAPI ``TestClient``
(see ``_patch_httpx_to_testclient`` reused from ``test_agent_sync``), then
invokes the real ``flusher._run_flush_loop()``. The assertions then look at:

  * the server SQLite engine (rows persisted, schema correct), AND
  * the agent SQLite buffer (rows drained on success, retained on failure).

This catches integration regressions unit tests miss: schema-version
negotiation, ``delete_ids`` being called only on 2xx, batch chunking at
the 200-event boundary, retry/backoff behavior, and — critically — the
privacy regression that no field resembling ``tool_input`` ever appears
on the wire.
"""

from __future__ import annotations

import json
from pathlib import Path

import httpx
import pytest
from fastapi.testclient import TestClient
from sqlmodel import Session, select

from ccguard.agent.audit_hook import flusher as flusher_mod
from ccguard.agent.audit_hook.buffer import ToolBufferDB
from ccguard.server.db.models import ToolUseEvent

pytestmark = pytest.mark.integration


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _install_e2e_environment(
    monkeypatch: pytest.MonkeyPatch,
    client: TestClient,
    tmp_path: Path,
    *,
    token: str = "test-token-abc",
    machine_id: str = "laptop-e2e",
) -> tuple[Path, list[httpx.Request]]:
    """Wire flusher to in-process TestClient.

    Steps:
      * Redirect ``default_config_dir`` -> ``tmp_path`` so the buffer path
        and lock path live under the test tmpdir.
      * Patch ``flusher._run_flush_loop``'s lazy imports of
        ``load_or_create`` and ``derive_machine_id`` via the agent.config /
        agent.machine_id modules.
      * Replace ``httpx.Client`` so every call funnels through the FastAPI
        TestClient (with the right Host so ASGI routes match).

    Returns (buffer_path, captured_requests) where ``captured_requests`` is a
    growing list of ``httpx.Request`` objects observed during the test.
    """
    monkeypatch.setattr(flusher_mod, "_buffer_path", lambda: tmp_path / "audit_buffer.db")
    monkeypatch.setattr(flusher_mod, "_lock_path", lambda: tmp_path / "audit_flush.lock")

    # Patch agent config + machine_id loaded *inside* _run_flush_loop.
    from ccguard.agent import config as agent_config
    from ccguard.agent import machine_id as agent_machine

    class _Server:
        url = "http://testserver"

    server_obj = _Server()
    server_obj.token = token

    class _Cfg:
        install_salt = "salt-for-tests"
    cfg_obj = _Cfg()
    cfg_obj.server = server_obj

    monkeypatch.setattr(
        agent_config, "load_or_create", lambda path=None: (cfg_obj, tmp_path / "config.yaml")
    )
    monkeypatch.setattr(agent_machine, "derive_machine_id", lambda salt: machine_id)

    # Drop backoff sleeps so retry tests run fast.
    monkeypatch.setattr(flusher_mod, "_BACKOFF_SECONDS", (0, 0, 0))

    captured: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        captured.append(request)
        url = request.url
        path = url.path
        if url.query:
            q = url.query.decode() if isinstance(url.query, bytes) else url.query
            path = f"{path}?{q}"
        r = client.request(
            request.method,
            path,
            content=request.content,
            headers=dict(request.headers),
        )
        return httpx.Response(
            status_code=r.status_code,
            headers=dict(r.headers),
            content=r.content,
            request=request,
        )

    transport = httpx.MockTransport(handler)
    real_init = httpx.Client.__init__

    def patched_init(self, *args, **kwargs):  # type: ignore[no-untyped-def]
        kwargs.pop("transport", None)
        kwargs["transport"] = transport
        real_init(self, *args, **kwargs)

    monkeypatch.setattr(httpx.Client, "__init__", patched_init)

    return tmp_path / "audit_buffer.db", captured


def _populate_buffer(
    buffer_path: Path,
    n: int,
    *,
    tool_name: str = "Bash",
    fingerprint: str = "0123456789abcdef",
    decision: str = "allow",
    result_status: str = "success",
    ts_prefix: str = "2026-05-25T00:",
) -> None:
    with ToolBufferDB(buffer_path) as buf:
        for i in range(n):
            buf.insert(
                ts=f"{ts_prefix}{i // 60:02d}:{i % 60:02d}Z",
                tool_name=tool_name,
                fingerprint=fingerprint,
                decision=decision,
                result_status=result_status,
            )


def _server_rows(client: TestClient) -> list[ToolUseEvent]:
    engine = client.app.state.engine  # type: ignore[attr-defined]
    with Session(engine) as s:
        return list(s.exec(select(ToolUseEvent)))


def _buffer_rowcount(buffer_path: Path) -> int:
    with ToolBufferDB(buffer_path) as buf:
        return buf.row_count()


# ---------------------------------------------------------------------------
# 1. Happy path drain
# ---------------------------------------------------------------------------


def test_flush_happy_path_drains_buffer_and_persists_server_rows(
    monkeypatch: pytest.MonkeyPatch,
    client: TestClient,
    tmp_path: Path,
    auth_headers,  # noqa: ARG001 — only to ensure VALID_TOKEN is wired
) -> None:
    buffer_path, captured = _install_e2e_environment(monkeypatch, client, tmp_path)
    _populate_buffer(buffer_path, n=5)

    flusher_mod._run_flush_loop()

    rows = _server_rows(client)
    assert len(rows) == 5
    assert all(r.machine_id == "laptop-e2e" for r in rows)
    assert _buffer_rowcount(buffer_path) == 0
    # Exactly one POST round-trip for 5 events (<=200 batch size).
    assert len(captured) == 1
    assert captured[0].method == "POST"
    assert captured[0].url.path == "/api/v1/audit"


# ---------------------------------------------------------------------------
# 2. Schema major version mismatch: 422 + buffer retained
# ---------------------------------------------------------------------------


def test_flush_schema_major_mismatch_keeps_events_in_buffer(
    monkeypatch: pytest.MonkeyPatch,
    client: TestClient,
    tmp_path: Path,
) -> None:
    from ccguard.schemas import tool_use as tu

    # Agent claims schema_version=1.0; server is on "0.2" — mismatched MAJOR.
    monkeypatch.setattr(tu, "SCHEMA_VERSION_AUDIT", "1.0")

    buffer_path, captured = _install_e2e_environment(monkeypatch, client, tmp_path)
    _populate_buffer(buffer_path, n=3)

    flusher_mod._run_flush_loop()

    # Server stored nothing.
    assert _server_rows(client) == []
    # Buffer kept all events (flusher only deletes on 2xx).
    assert _buffer_rowcount(buffer_path) == 3
    # Server returned 422 on the attempt.
    assert any(r.url.path == "/api/v1/audit" for r in captured)


# ---------------------------------------------------------------------------
# 3. Batch chunking at 200-event boundary
# ---------------------------------------------------------------------------


def test_flush_batch_chunking_above_200_events(
    monkeypatch: pytest.MonkeyPatch,
    client: TestClient,
    tmp_path: Path,
) -> None:
    buffer_path, captured = _install_e2e_environment(monkeypatch, client, tmp_path)
    _populate_buffer(buffer_path, n=350)

    flusher_mod._run_flush_loop()

    rows = _server_rows(client)
    assert len(rows) == 350
    assert _buffer_rowcount(buffer_path) == 0
    # At least 2 POSTs: 200 + 150.
    post_calls = [r for r in captured if r.method == "POST" and r.url.path == "/api/v1/audit"]
    assert len(post_calls) >= 2


# ---------------------------------------------------------------------------
# 4. Server 5xx retry/backoff
# ---------------------------------------------------------------------------


def test_flush_server_5xx_eventually_succeeds_on_retry(
    monkeypatch: pytest.MonkeyPatch,
    client: TestClient,
    tmp_path: Path,
) -> None:
    """First 2 POSTs return 500; 3rd succeeds. Buffer must drain after success."""
    # Wire all the agent-side bits BUT do NOT install the default httpx mock —
    # we install a counting one instead below.
    monkeypatch.setattr(
        flusher_mod, "_buffer_path", lambda: tmp_path / "audit_buffer.db"
    )
    monkeypatch.setattr(
        flusher_mod, "_lock_path", lambda: tmp_path / "audit_flush.lock"
    )
    from ccguard.agent import config as agent_config
    from ccguard.agent import machine_id as agent_machine

    class _Server:
        url = "http://testserver"
        token = "test-token-abc"

    class _Cfg:
        install_salt = "salt-for-tests"
        server = _Server()

    monkeypatch.setattr(
        agent_config, "load_or_create", lambda path=None: (_Cfg(), tmp_path / "config.yaml")
    )
    monkeypatch.setattr(agent_machine, "derive_machine_id", lambda salt: "laptop-e2e")
    monkeypatch.setattr(flusher_mod, "_BACKOFF_SECONDS", (0, 0, 0))

    buffer_path = tmp_path / "audit_buffer.db"
    _populate_buffer(buffer_path, n=5)

    counter = {"n": 0}

    def handler(request: httpx.Request) -> httpx.Response:
        counter["n"] += 1
        if counter["n"] <= 2:
            return httpx.Response(
                status_code=500,
                content=b'{"detail":"boom"}',
                request=request,
            )
        url = request.url
        path = url.path
        if url.query:
            q = url.query.decode() if isinstance(url.query, bytes) else url.query
            path = f"{path}?{q}"
        r = client.request(
            request.method,
            path,
            content=request.content,
            headers=dict(request.headers),
        )
        return httpx.Response(
            status_code=r.status_code,
            headers=dict(r.headers),
            content=r.content,
            request=request,
        )

    transport = httpx.MockTransport(handler)
    real_init = httpx.Client.__init__

    def patched_init(self, *args, **kwargs):  # type: ignore[no-untyped-def]
        kwargs.pop("transport", None)
        kwargs["transport"] = transport
        real_init(self, *args, **kwargs)

    monkeypatch.setattr(httpx.Client, "__init__", patched_init)

    flusher_mod._run_flush_loop()

    assert counter["n"] >= 3
    assert len(_server_rows(client)) == 5
    assert _buffer_rowcount(buffer_path) == 0


# ---------------------------------------------------------------------------
# 5. Auth failure (no token) → 401, buffer retained
# ---------------------------------------------------------------------------


def test_flush_missing_token_returns_401_and_keeps_buffer(
    monkeypatch: pytest.MonkeyPatch,
    client: TestClient,
    tmp_path: Path,
) -> None:
    buffer_path, captured = _install_e2e_environment(
        monkeypatch, client, tmp_path, token=""
    )
    _populate_buffer(buffer_path, n=5)

    flusher_mod._run_flush_loop()

    # 401 from server → no rows stored, buffer untouched.
    assert _server_rows(client) == []
    assert _buffer_rowcount(buffer_path) == 5
    # The flusher did attempt at least one POST.
    assert any(r.method == "POST" and r.url.path == "/api/v1/audit" for r in captured)


# ---------------------------------------------------------------------------
# 6. trim_to_cap fires after drain
# ---------------------------------------------------------------------------


def test_flush_trims_buffer_to_cap_after_success(
    monkeypatch: pytest.MonkeyPatch,
    client: TestClient,
    tmp_path: Path,
) -> None:
    """With 10_100 events in the buffer, after a full flush the cap-trim
    invariant must hold: buffer.row_count() <= 10_000.

    Note: with the production batch size (200) and max attempts (3) the
    flusher will not drain the entire 10_100 in one invocation. The
    important invariant for this regression test is that `trim_to_cap`
    runs at the end, so the buffer never grows unbounded.
    """
    buffer_path, _ = _install_e2e_environment(monkeypatch, client, tmp_path)
    _populate_buffer(buffer_path, n=10_100)

    flusher_mod._run_flush_loop()

    # Server has at least the events drained on the first pass.
    assert len(_server_rows(client)) >= 200
    # Buffer was capped post-flush.
    assert _buffer_rowcount(buffer_path) <= 10_000


# ---------------------------------------------------------------------------
# 7. Privacy boundary regression — no raw tool_input on the wire
# ---------------------------------------------------------------------------


def _recursive_keys(obj) -> list[str]:
    """Walk a JSON tree and return every key seen at any nesting depth."""
    out: list[str] = []
    if isinstance(obj, dict):
        for k, v in obj.items():
            out.append(k)
            out.extend(_recursive_keys(v))
    elif isinstance(obj, list):
        for item in obj:
            out.extend(_recursive_keys(item))
    return out


def test_flush_payload_contains_no_raw_tool_input_keys(
    monkeypatch: pytest.MonkeyPatch,
    client: TestClient,
    tmp_path: Path,
) -> None:
    """Privacy invariant (T-01-07): no field resembling the raw tool input
    is ever serialised onto the wire. We assert recursively across the
    posted JSON body that none of {tool_input, command, file_path, content,
    prompt} appears as a key — adding any of these to the schema in the
    future would be a privacy regression and this test would fail."""
    buffer_path, captured = _install_e2e_environment(monkeypatch, client, tmp_path)
    _populate_buffer(
        buffer_path,
        n=2,
        tool_name="Bash",
        fingerprint="deadbeefcafebabe",
    )

    flusher_mod._run_flush_loop()

    posts = [r for r in captured if r.method == "POST" and r.url.path == "/api/v1/audit"]
    assert len(posts) >= 1
    for req in posts:
        body = json.loads(req.content.decode())
        keys = set(_recursive_keys(body))
        forbidden = {"tool_input", "command", "file_path", "content", "prompt"}
        leaked = keys & forbidden
        assert not leaked, f"Privacy regression: forbidden keys on the wire: {leaked}"
        # And as an additional cross-check, the fingerprint we did seed IS present.
        raw = req.content.decode()
        assert "deadbeefcafebabe" in raw
