"""Integration tests for POST /api/v1/scan-content and GET /api/v1/scanner-config (Plan 03-04).

Covers Plan 03-04 Task 1 acceptance criteria:
(a) /scanner-config returns enabled=false when ANTHROPIC_API_KEY unset
(b) /scanner-config returns enabled=true when env key set AND llm_scanner_enabled=true
(c) POST /scan-content rejects unauthenticated requests
(d) POST /scan-content happy path → file_hash, risk_score, severity, cached=false
(e) Repeat with identical content → cached=true, no new LLMCallLog
(f) Oversized content (>1 MiB) → per-item error="content_too_large"
(g) Medium content (>100 KiB <1 MiB) → truncated=true, scan still runs
(h) Budget exhausted mid-batch → first items succeed, later get error="budget_exhausted"

The endpoint uses the real :class:`ScanService` against in-memory SQLite; only
``LLMClient.scan_content`` is mocked via dependency override.
"""

from __future__ import annotations

import base64
from collections.abc import Iterator
from datetime import UTC, datetime
from pathlib import Path

import pytest
import yaml
from fastapi.testclient import TestClient
from sqlmodel import Session, select

from ccguard.schemas import Policy, PolicyMeta
from ccguard.server.api.scan import get_scan_service
from ccguard.server.config import ServerConfig, TokenEntry
from ccguard.server.db.models import LLMCallLog, ScanResult, SettingsRecord
from ccguard.server.db.session import init_db, make_engine
from ccguard.server.main import create_app
from ccguard.server.policy_loader import PolicyLoader
from ccguard.server.services.llm_client import ScanOutcome
from ccguard.server.services.scan_service import ScanService
from ccguard.server.services.settings_service import seed_llm_settings

VALID_TOKEN = "scan-test-token"


class _ScriptedLLM:
    """Mock LLMClient. Returns scripted outcomes by file_path; unknown paths
    fall back to a default benign outcome."""

    def __init__(self, script: dict[str, ScanOutcome] | None = None, default: ScanOutcome | None = None) -> None:
        self.script = script or {}
        self.default = default or ScanOutcome(
            risk_score=10,
            category="benign",
            rationale="ok",
            input_tokens=100,
            output_tokens=20,
            cost_cents=1,
            model="claude-haiku-4-5-20251001",
        )
        self.calls: list[tuple[str, str, str]] = []

    async def scan_content(self, content: str, file_path: str, scope: str):
        self.calls.append((content, file_path, scope))
        return self.script.get(file_path, self.default)


def _make_client(
    tmp_path: Path,
    *,
    api_key: str | None = "sk-ant-fake",
    enabled: bool = True,
    budget: int = 100,
    llm: _ScriptedLLM | None = None,
) -> tuple[TestClient, _ScriptedLLM, object]:
    policy_path = tmp_path / "policy.yaml"
    policy_path.write_text(
        yaml.safe_dump(
            Policy(meta=PolicyMeta(revision=1, updated_at=datetime.now(UTC))).model_dump(mode="json"),
            sort_keys=False,
        )
    )
    db_path = tmp_path / "scan-test.db"
    cfg = ServerConfig(
        tokens=[TokenEntry(value=VALID_TOKEN, label="test")],
        policy_path=str(policy_path),
        db_url=f"sqlite:///{db_path}",
        anthropic_api_key=api_key,
    )

    app = create_app()
    engine = make_engine(cfg.db_url)
    init_db(engine)
    with Session(engine) as s:
        seed_llm_settings(s)
        e_row = s.exec(select(SettingsRecord).where(SettingsRecord.key == "llm_scanner_enabled")).first()
        if e_row is not None:
            e_row.value = "true" if enabled else "false"
        b_row = s.exec(select(SettingsRecord).where(SettingsRecord.key == "daily_call_budget")).first()
        if b_row is not None:
            b_row.value = str(budget)
        s.commit()

    app.state.config = cfg
    app.state.engine = engine
    app.state.policy_loader = PolicyLoader(file_path=policy_path, engine=engine)

    used_llm = llm or _ScriptedLLM()
    svc = ScanService(engine=engine, llm_client=used_llm)
    app.state.scan_service = svc

    def _override() -> ScanService:
        return svc

    app.dependency_overrides[get_scan_service] = _override

    client = TestClient(app)
    client.__enter__()
    # lifespan rewrites state from env — restore the test config after startup.
    client.app.state.config = cfg  # type: ignore[attr-defined]
    client.app.state.engine = engine  # type: ignore[attr-defined]
    client.app.state.policy_loader = PolicyLoader(file_path=policy_path, engine=engine)  # type: ignore[attr-defined]
    client.app.state.scan_service = svc  # type: ignore[attr-defined]
    return client, used_llm, engine


@pytest.fixture
def auth_headers() -> dict[str, str]:
    return {"X-CCGuard-Token": VALID_TOKEN}


def _b64(text: str) -> str:
    return base64.b64encode(text.encode("utf-8")).decode("ascii")


# -----------------------------------------------------------------------------
# (a) scanner-config disabled when ANTHROPIC_API_KEY unset
# -----------------------------------------------------------------------------


def test_scanner_config_disabled_without_api_key(tmp_path: Path, auth_headers: dict[str, str]) -> None:
    client, _llm, _eng = _make_client(tmp_path, api_key=None, enabled=True)
    try:
        r = client.get("/api/v1/scanner-config", headers=auth_headers)
        assert r.status_code == 200
        body = r.json()
        assert body["enabled"] is False
        assert body["max_file_bytes"] == 1_048_576
        assert body["schema_version"] == 1
    finally:
        client.__exit__(None, None, None)


# -----------------------------------------------------------------------------
# (b) scanner-config enabled when key set AND llm_scanner_enabled=true
# -----------------------------------------------------------------------------


def test_scanner_config_enabled_with_key_and_setting(tmp_path: Path, auth_headers: dict[str, str]) -> None:
    client, _llm, _eng = _make_client(tmp_path, api_key="sk-ant-fake", enabled=True)
    try:
        r = client.get("/api/v1/scanner-config", headers=auth_headers)
        assert r.status_code == 200
        assert r.json()["enabled"] is True
    finally:
        client.__exit__(None, None, None)


def test_scanner_config_disabled_when_setting_off(tmp_path: Path, auth_headers: dict[str, str]) -> None:
    client, _llm, _eng = _make_client(tmp_path, api_key="sk-ant-fake", enabled=False)
    try:
        r = client.get("/api/v1/scanner-config", headers=auth_headers)
        assert r.json()["enabled"] is False
    finally:
        client.__exit__(None, None, None)


# -----------------------------------------------------------------------------
# (c) Unauthenticated POST rejected
# -----------------------------------------------------------------------------


def test_scan_content_rejects_missing_token(tmp_path: Path) -> None:
    client, _llm, _eng = _make_client(tmp_path)
    try:
        r = client.post(
            "/api/v1/scan-content",
            json={"items": [{"file_path": "a.md", "scope": "agent", "content_b64": _b64("hi")}]},
        )
        assert r.status_code == 401
    finally:
        client.__exit__(None, None, None)


def test_scanner_config_rejects_missing_token(tmp_path: Path) -> None:
    client, _llm, _eng = _make_client(tmp_path)
    try:
        r = client.get("/api/v1/scanner-config")
        assert r.status_code == 401
    finally:
        client.__exit__(None, None, None)


# -----------------------------------------------------------------------------
# (d) Happy path
# -----------------------------------------------------------------------------


def test_scan_content_happy_path_one_item(tmp_path: Path, auth_headers: dict[str, str]) -> None:
    llm = _ScriptedLLM(
        {
            "a.md": ScanOutcome(
                risk_score=42,
                category="jailbreak",
                rationale="suspicious",
                input_tokens=120,
                output_tokens=22,
                cost_cents=2,
                model="claude-haiku-4-5-20251001",
            )
        }
    )
    client, used_llm, _eng = _make_client(tmp_path, llm=llm)
    try:
        r = client.post(
            "/api/v1/scan-content",
            headers=auth_headers,
            json={"items": [{"file_path": "a.md", "scope": "agent", "content_b64": _b64("hello")}]},
        )
        assert r.status_code == 200, r.text
        body = r.json()
        assert body["schema_version"] == 1
        assert len(body["items"]) == 1
        item = body["items"][0]
        assert item["error"] is None
        assert item["file_path"] == "a.md"
        assert item["file_hash"] and len(item["file_hash"]) == 64
        assert item["risk_score"] == 42
        assert item["category"] == "jailbreak"
        assert item["severity"] == "warn"  # 30-70 → warn
        assert item["cached"] is False
        assert item["truncated"] is False
        assert len(used_llm.calls) == 1
    finally:
        client.__exit__(None, None, None)


# -----------------------------------------------------------------------------
# (e) Second identical POST → cached=true, no new LLMCallLog
# -----------------------------------------------------------------------------


def test_scan_content_cache_hit_on_repeat(tmp_path: Path, auth_headers: dict[str, str]) -> None:
    client, used_llm, engine = _make_client(tmp_path)
    try:
        payload = {"items": [{"file_path": "a.md", "scope": "agent", "content_b64": _b64("X")}]}
        r1 = client.post("/api/v1/scan-content", headers=auth_headers, json=payload)
        assert r1.json()["items"][0]["cached"] is False

        r2 = client.post("/api/v1/scan-content", headers=auth_headers, json=payload)
        item = r2.json()["items"][0]
        assert item["cached"] is True
        assert item["file_hash"] == r1.json()["items"][0]["file_hash"]

        # Only one LLM call, only one LLMCallLog row.
        assert len(used_llm.calls) == 1
        with Session(engine) as s:
            assert len(list(s.exec(select(LLMCallLog)))) == 1
            assert len(list(s.exec(select(ScanResult)))) == 1
    finally:
        client.__exit__(None, None, None)


# -----------------------------------------------------------------------------
# (f) Oversized (>1 MiB) → content_too_large
# -----------------------------------------------------------------------------


def test_scan_content_oversized_rejected_per_item(tmp_path: Path, auth_headers: dict[str, str]) -> None:
    client, used_llm, _eng = _make_client(tmp_path)
    try:
        big = "A" * (1_048_577)  # 1 MiB + 1 byte
        r = client.post(
            "/api/v1/scan-content",
            headers=auth_headers,
            json={
                "items": [
                    {"file_path": "ok.md", "scope": "agent", "content_b64": _b64("ok")},
                    {"file_path": "big.md", "scope": "agent", "content_b64": _b64(big)},
                ]
            },
        )
        assert r.status_code == 200
        items = r.json()["items"]
        assert items[0]["error"] is None
        assert items[1]["error"] == "content_too_large"
        assert items[1]["file_hash"] is None
        # LLM was only called for the small item.
        assert len(used_llm.calls) == 1
    finally:
        client.__exit__(None, None, None)


# -----------------------------------------------------------------------------
# (g) Medium (>100KiB, <1MiB) → truncated=true, scan runs
# -----------------------------------------------------------------------------


def test_scan_content_truncates_above_soft_cap(tmp_path: Path, auth_headers: dict[str, str]) -> None:
    client, used_llm, _eng = _make_client(tmp_path)
    try:
        medium = "M" * (102_400 + 1024)  # ~101 KiB
        r = client.post(
            "/api/v1/scan-content",
            headers=auth_headers,
            json={"items": [{"file_path": "m.md", "scope": "agent", "content_b64": _b64(medium)}]},
        )
        assert r.status_code == 200
        item = r.json()["items"][0]
        assert item["error"] is None
        assert item["truncated"] is True
        assert item["risk_score"] is not None
        # The LLM was called with truncated content (≤100 KiB).
        assert len(used_llm.calls) == 1
        sent_content = used_llm.calls[0][0]
        assert len(sent_content) <= 102_400
    finally:
        client.__exit__(None, None, None)


# -----------------------------------------------------------------------------
# (h) Budget exhausted mid-batch → first items succeed, later get error
# -----------------------------------------------------------------------------


def test_scan_content_budget_exhausted_mid_batch(tmp_path: Path, auth_headers: dict[str, str]) -> None:
    client, _llm, _eng = _make_client(tmp_path, budget=2)
    try:
        r = client.post(
            "/api/v1/scan-content",
            headers=auth_headers,
            json={
                "items": [
                    {"file_path": "a.md", "scope": "agent", "content_b64": _b64("a")},
                    {"file_path": "b.md", "scope": "agent", "content_b64": _b64("b")},
                    {"file_path": "c.md", "scope": "agent", "content_b64": _b64("c")},
                    {"file_path": "d.md", "scope": "agent", "content_b64": _b64("d")},
                ]
            },
        )
        assert r.status_code == 200
        items = r.json()["items"]
        assert items[0]["error"] is None and items[1]["error"] is None
        # Items 3 and 4 should be budget_exhausted.
        assert items[2]["error"] == "budget_exhausted"
        assert items[3]["error"] == "budget_exhausted"
    finally:
        client.__exit__(None, None, None)


# -----------------------------------------------------------------------------
# (i) Scanner disabled → every item gets scanner_disabled
# -----------------------------------------------------------------------------


def test_scan_content_scanner_disabled_all_items(tmp_path: Path, auth_headers: dict[str, str]) -> None:
    client, _llm, _eng = _make_client(tmp_path, enabled=False)
    try:
        r = client.post(
            "/api/v1/scan-content",
            headers=auth_headers,
            json={"items": [{"file_path": "a.md", "scope": "agent", "content_b64": _b64("x")}]},
        )
        assert r.status_code == 200
        assert r.json()["items"][0]["error"] == "scanner_disabled"
    finally:
        client.__exit__(None, None, None)


# -----------------------------------------------------------------------------
# (j) Raw content never appears in server logs
# -----------------------------------------------------------------------------


def test_scan_content_does_not_log_raw_content(
    tmp_path: Path, auth_headers: dict[str, str], caplog: pytest.LogCaptureFixture
) -> None:
    import logging

    secret = "SUPER-SECRET-NEEDLE-9f3a82b7"
    client, _llm, _eng = _make_client(tmp_path)
    try:
        with caplog.at_level(logging.DEBUG, logger="ccguard"):
            r = client.post(
                "/api/v1/scan-content",
                headers=auth_headers,
                json={"items": [{"file_path": "a.md", "scope": "agent", "content_b64": _b64(secret)}]},
            )
        assert r.status_code == 200
        for record in caplog.records:
            assert secret not in record.getMessage(), (
                f"raw content leaked into server log: {record.getMessage()!r}"
            )
    finally:
        client.__exit__(None, None, None)
