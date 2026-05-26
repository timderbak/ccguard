"""End-to-end vertical-slice tests for Phase 3 LLM content scanner (Plan 03-06).

These tests stitch together every layer the previous plans tested in isolation:

  agent.collect_scannable_files (mask + b64)
    → agent.send_scan_batch (httpx ASGITransport)
      → POST /api/v1/scan-content
        → ScanService.scan_file (cache + budget + lock)
          → mocked anthropic.AsyncAnthropic (tool_use response)
            → ScanResult + LLMCallLog + FindingRecord persistence
              → GET /findings UI (Jinja templates, badge color)

All Anthropic I/O is mocked at the SDK boundary
(``anthropic.AsyncAnthropic.messages.create``) so the tests never touch the
network. The mock returns a tool_use response shaped like Anthropic's real
``Message`` object (block has ``type``, ``name``, ``input``; message has
``content`` list and ``usage`` with ``input_tokens``/``output_tokens``).
"""

from __future__ import annotations

import base64
import json
from collections.abc import Iterator
from datetime import UTC, datetime
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import AsyncMock, patch

import pytest
import yaml
from fastapi.testclient import TestClient
from sqlmodel import Session, select

from ccguard.schemas import Policy, PolicyMeta
from ccguard.server.api.scan import get_scan_service
from ccguard.server.config import ServerConfig, TokenEntry
from ccguard.server.db.models import (
    FindingRecord,
    LLMCallLog,
    ScanResult,
    SettingsRecord,
    WebSession,
)
from ccguard.server.db.session import init_db, make_engine
from ccguard.server.main import create_app
from ccguard.server.policy_loader import PolicyLoader
from ccguard.server.services.auth_service import create_session, hash_password
from ccguard.server.services.llm_client import LLMClient
from ccguard.server.services.scan_service import ScanService
from ccguard.server.services.settings_service import seed_llm_settings

VALID_TOKEN = "e2e-test-token"


# ----- Mock helpers ---------------------------------------------------------


def _mock_message(
    *,
    risk_score: int,
    category: str,
    rationale: str = "e2e",
    input_tokens: int = 120,
    output_tokens: int = 30,
) -> SimpleNamespace:
    """Build a SimpleNamespace that mimics anthropic.types.Message enough for
    :func:`ccguard.server.services.llm_client._extract_tool_use`.
    """
    block = SimpleNamespace(
        type="tool_use",
        name="report_risk",
        input={
            "risk_score": risk_score,
            "category": category,
            "rationale": rationale,
        },
    )
    return SimpleNamespace(
        content=[block],
        usage=SimpleNamespace(
            input_tokens=input_tokens,
            output_tokens=output_tokens,
        ),
    )


def _make_e2e_app(
    tmp_path: Path,
    *,
    enabled: bool = True,
    budget: int = 100,
    api_key: str = "sk-ant-fake",
) -> tuple[TestClient, AsyncMock, object]:
    """Spin up TestClient backed by an in-memory SQLite and a real ScanService
    whose LLMClient is wrapped so ``messages.create`` is an AsyncMock.

    The mock is patched at the import boundary inside ``llm_client``
    (``anthropic.AsyncAnthropic``); the returned AsyncMock is the mock for
    ``messages.create``. Tests configure ``mock.side_effect``/``return_value``
    and assert ``mock.call_count``.
    """
    policy_path = tmp_path / "policy.yaml"
    policy_path.write_text(
        yaml.safe_dump(
            Policy(meta=PolicyMeta(revision=1, updated_at=datetime.now(UTC))).model_dump(mode="json"),
            sort_keys=False,
        )
    )
    db_path = tmp_path / "e2e.db"
    cfg = ServerConfig(
        tokens=[TokenEntry(value=VALID_TOKEN, label="test")],
        policy_path=str(policy_path),
        db_url=f"sqlite:///{db_path}",
        anthropic_api_key=api_key,
        session_secret="test-secret",
        admin_user="admin",
        admin_password_hash=hash_password("hunter2"),
    )

    app = create_app()
    engine = make_engine(cfg.db_url)
    init_db(engine)
    with Session(engine) as s:
        seed_llm_settings(s)
        e_row = s.exec(
            select(SettingsRecord).where(SettingsRecord.key == "llm_scanner_enabled")
        ).first()
        if e_row is not None:
            e_row.value = "true" if enabled else "false"
        b_row = s.exec(
            select(SettingsRecord).where(SettingsRecord.key == "daily_call_budget")
        ).first()
        if b_row is not None:
            b_row.value = str(budget)
        s.commit()

    # Patch the Anthropic SDK at the import site inside llm_client.
    mock_create = AsyncMock()
    fake_anthropic = type("FakeAnthropic", (), {})()
    fake_anthropic.messages = SimpleNamespace(create=mock_create)

    def _fake_client_factory(api_key: str):  # noqa: ARG001
        return fake_anthropic

    patcher = patch(
        "ccguard.server.services.llm_client.anthropic.AsyncAnthropic",
        side_effect=_fake_client_factory,
    )
    patcher.start()

    llm_client = LLMClient(api_key=api_key)
    svc = ScanService(engine=engine, llm_client=llm_client)

    app.state.config = cfg
    app.state.engine = engine
    app.state.policy_loader = PolicyLoader(file_path=policy_path, engine=engine)
    app.state.scan_service = svc
    app.dependency_overrides[get_scan_service] = lambda: svc

    client = TestClient(app)
    client.__enter__()
    # lifespan rewrites state from env; restore.
    client.app.state.config = cfg  # type: ignore[attr-defined]
    client.app.state.engine = engine  # type: ignore[attr-defined]
    client.app.state.policy_loader = PolicyLoader(file_path=policy_path, engine=engine)  # type: ignore[attr-defined]
    client.app.state.scan_service = svc  # type: ignore[attr-defined]

    # Stash the patcher so the test's finalizer can stop it.
    client._mock_patcher = patcher  # type: ignore[attr-defined]
    return client, mock_create, engine


def _shutdown(client: TestClient) -> None:
    patcher = getattr(client, "_mock_patcher", None)
    try:
        client.__exit__(None, None, None)
    finally:
        if patcher is not None:
            patcher.stop()


def _b64(text: str) -> str:
    return base64.b64encode(text.encode("utf-8")).decode("ascii")


def _admin_login(client: TestClient) -> tuple[str, str]:
    """Create an admin session row directly and return (sid, csrf). Bypasses
    the password form so UI tests stay focused on the rendering target."""
    from ccguard.server.web.csrf import generate_csrf_token

    engine = client.app.state.engine
    with Session(engine) as s:
        sid = create_session(s, user_id="admin")
    csrf = generate_csrf_token(secret="test-secret", session_id=sid)
    return sid, csrf


# ----- Tests ----------------------------------------------------------------


def test_scanner_e2e_happy_path(tmp_path: Path) -> None:
    """Drive every layer: scanner-config probe → POST → DB → UI badge."""
    client, mock_create, engine = _make_e2e_app(tmp_path)
    try:
        mock_create.return_value = _mock_message(
            risk_score=85, category="jailbreak", rationale="e2e suspicious"
        )

        # --- agent collects two files from a synthetic ~/.claude home ---
        from ccguard.agent.inventory_scan import collect_scannable_files

        claude_home = tmp_path / "claude_home"
        agents_dir = claude_home / "agents"
        skills_dir = claude_home / "skills" / "demo"
        agents_dir.mkdir(parents=True)
        skills_dir.mkdir(parents=True)
        (agents_dir / "foo.md").write_text("malicious agent content e2e foo")
        (skills_dir / "SKILL.md").write_text("malicious skill content e2e bar")

        items = collect_scannable_files(claude_home)
        assert len(items) == 2, "collect_scannable_files must pick up both files"

        # --- agent probes /scanner-config: enabled=true ---
        r_cfg = client.get(
            "/api/v1/scanner-config",
            headers={"X-CCGuard-Token": VALID_TOKEN},
        )
        assert r_cfg.status_code == 200
        assert r_cfg.json()["enabled"] is True  # (a)

        # --- agent POSTs the batch directly via the TestClient ---
        r_scan = client.post(
            "/api/v1/scan-content",
            headers={"X-CCGuard-Token": VALID_TOKEN},
            json={
                "items": [
                    {"file_path": it.file_path, "scope": it.scope, "content_b64": it.content_b64}
                    for it in items
                ]
            },
        )
        assert r_scan.status_code == 200, r_scan.text
        body = r_scan.json()
        assert len(body["items"]) == 2  # (b)
        for item in body["items"]:
            assert item["error"] is None
            assert item["risk_score"] == 85
            assert item["severity"] == "critical"

        # --- DB invariants ---
        with Session(engine) as s:
            scans = list(s.exec(select(ScanResult)))
            logs = list(s.exec(select(LLMCallLog)))
            finds = list(s.exec(select(FindingRecord).where(
                FindingRecord.rule_id == "llm.scan.jailbreak"
            )))
        assert len(scans) == 2  # (c)
        assert len(logs) == 2  # (d) two LLMCallLog rows
        for log_row in logs:
            assert log_row.model == "claude-haiku-4-5-20251001"
        assert len(finds) == 2  # (e)
        for fr in finds:
            assert fr.severity == "critical"
            assert fr.rule_id == "llm.scan.jailbreak"

        # --- UI ---
        sid, _csrf = _admin_login(client)
        r_ui = client.get("/findings", cookies={"ccg_session": sid})
        assert r_ui.status_code == 200, r_ui.text
        html = r_ui.content
        assert b"bg-red-600" in html  # (f) critical badge
        assert "Пересканировать".encode("utf-8") in html
    finally:
        _shutdown(client)


def test_cache_hit_avoids_second_call(tmp_path: Path) -> None:
    """Identical content posted twice → mock.call_count stays at 1, cached=True on second."""
    client, mock_create, _engine = _make_e2e_app(tmp_path)
    try:
        mock_create.return_value = _mock_message(risk_score=10, category="benign")
        payload = {
            "items": [
                {"file_path": "a.md", "scope": "agent", "content_b64": _b64("identical")}
            ]
        }
        r1 = client.post(
            "/api/v1/scan-content",
            headers={"X-CCGuard-Token": VALID_TOKEN},
            json=payload,
        )
        assert r1.status_code == 200
        assert r1.json()["items"][0]["cached"] is False
        assert mock_create.call_count == 1

        r2 = client.post(
            "/api/v1/scan-content",
            headers={"X-CCGuard-Token": VALID_TOKEN},
            json=payload,
        )
        assert r2.status_code == 200
        assert r2.json()["items"][0]["cached"] is True
        assert mock_create.call_count == 1, "cache hit must not trigger a second Anthropic call"
    finally:
        _shutdown(client)


def test_budget_exhausted_mid_batch(tmp_path: Path) -> None:
    """Budget=2, send 3 distinct items → first 2 succeed, third gets
    error='budget_exhausted'; exactly 2 LLMCallLog rows."""
    client, mock_create, engine = _make_e2e_app(tmp_path, budget=2)
    try:
        mock_create.return_value = _mock_message(risk_score=10, category="benign")
        r = client.post(
            "/api/v1/scan-content",
            headers={"X-CCGuard-Token": VALID_TOKEN},
            json={
                "items": [
                    {"file_path": "a.md", "scope": "agent", "content_b64": _b64("alpha")},
                    {"file_path": "b.md", "scope": "agent", "content_b64": _b64("beta")},
                    {"file_path": "c.md", "scope": "agent", "content_b64": _b64("gamma")},
                ]
            },
        )
        assert r.status_code == 200, r.text
        items = r.json()["items"]
        assert items[0]["error"] is None and items[0]["risk_score"] == 10
        assert items[1]["error"] is None and items[1]["risk_score"] == 10
        assert items[2]["error"] == "budget_exhausted"
        # Exactly 2 LLM calls were billed.
        with Session(engine) as s:
            assert len(list(s.exec(select(LLMCallLog)))) == 2
        assert mock_create.call_count == 2
    finally:
        _shutdown(client)


def test_scanner_disabled_path(tmp_path: Path) -> None:
    """scanner disabled → agent's send_scan_batch returns skipped=scanner_disabled,
    zero LLMCallLog rows, UI usage counter shows 'Сканер выключен.'."""
    client, mock_create, engine = _make_e2e_app(tmp_path, enabled=False)
    try:
        from ccguard.agent.inventory_scan import send_scan_batch
        from ccguard.schemas.scan import ScanRequestItem

        # Probe /scanner-config directly: enabled=false.
        r_cfg = client.get(
            "/api/v1/scanner-config",
            headers={"X-CCGuard-Token": VALID_TOKEN},
        )
        assert r_cfg.json()["enabled"] is False

        # Drive the real agent send_scan_batch via an httpx.MockTransport that
        # forwards requests into the FastAPI TestClient (which is sync).
        import httpx

        def _handler(request: httpx.Request) -> httpx.Response:
            # Forward to the in-process TestClient. The TestClient API expects
            # a path (not a full URL) so strip the base.
            path = request.url.path
            if request.url.query:
                path = f"{path}?{request.url.query.decode('ascii')}"
            if request.method == "GET":
                r = client.get(
                    path,
                    headers=dict(request.headers),
                )
            else:
                r = client.request(
                    request.method,
                    path,
                    headers=dict(request.headers),
                    content=request.content,
                )
            return httpx.Response(
                status_code=r.status_code,
                headers=dict(r.headers),
                content=r.content,
            )

        transport = httpx.MockTransport(_handler)
        items = [
            ScanRequestItem(
                file_path="agents/foo.md", scope="agent", content_b64=_b64("hi")
            )
        ]
        result = send_scan_batch(
            server_url="http://test",
            token=VALID_TOKEN,
            items=items,
            transport=transport,
        )
        assert result == {"skipped": "scanner_disabled"}
        assert mock_create.call_count == 0

        with Session(engine) as s:
            assert len(list(s.exec(select(LLMCallLog)))) == 0

        # UI usage partial — admin login, then fetch partial.
        sid, _csrf = _admin_login(client)
        r_usage = client.get(
            "/_partials/settings/llm-usage",
            cookies={"ccg_session": sid},
        )
        assert r_usage.status_code == 200
        assert "Сканер выключен.".encode("utf-8") in r_usage.content
    finally:
        _shutdown(client)
