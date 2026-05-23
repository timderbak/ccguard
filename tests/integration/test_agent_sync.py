"""Integration: agent ↔ server полный sync-цикл."""

from __future__ import annotations

import time
from datetime import UTC, datetime
from pathlib import Path

import httpx
import pytest
import yaml
from fastapi.testclient import TestClient

from ccguard.agent.audit import make_audit_logger, write_audit
from ccguard.agent.config import AgentConfig
from ccguard.agent.sync import perform_sync
from ccguard.schemas import (
    AuditEntry,
    InventoryReport,
    PermissionsSnapshot,
    Policy,
    PolicyMeta,
)


@pytest.fixture
def agent_cfg(tmp_path: Path, client: TestClient) -> tuple[AgentConfig, Path, Path, Path]:
    """Конфиг агента + пути к кэшу/audit/cursor."""
    cfg = AgentConfig()
    cfg.server.token = "test-token-abc"
    cfg.install_salt = "salt"
    cache = tmp_path / "policy_cache.yaml"
    audit_path = tmp_path / "audit.log"
    cursor = tmp_path / "audit.cursor"
    return cfg, cache, audit_path, cursor


def _inv() -> InventoryReport:
    return InventoryReport(
        machine_id="machine-sync-test",
        timestamp=datetime.now(UTC),
        agent_version="0.1.0",
        os="linux",
        permissions=PermissionsSnapshot(),
    )


def _patch_httpx_to_testclient(monkeypatch: pytest.MonkeyPatch, client: TestClient) -> None:
    """Перехватить httpx.Client.request — отправлять через TestClient."""
    real_init = httpx.Client.__init__
    real_request = httpx.Client.request

    def fake_init(self, *args, **kwargs):  # type: ignore[no-untyped-def]
        kwargs["transport"] = httpx.WSGITransport(app=client.app)  # type: ignore[attr-defined]
        real_init(self, *args, **kwargs)

    # WSGITransport не работает с FastAPI (ASGI). Используем httpx.MockTransport
    # с обработчиком, делегирующим в TestClient.
    def handler(request: httpx.Request) -> httpx.Response:
        method = request.method
        # TestClient ждёт относительный путь
        url = request.url
        path = url.path
        if url.query:
            path = f"{path}?{url.query.decode() if isinstance(url.query, bytes) else url.query}"
        r = client.request(
            method,
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

    def patched_init(self, *args, **kwargs):  # type: ignore[no-untyped-def]
        kwargs.pop("transport", None)
        kwargs["transport"] = transport
        real_init(self, *args, **kwargs)

    monkeypatch.setattr(httpx.Client, "__init__", patched_init)


def test_sync_posts_inventory_and_fetches_policy(
    monkeypatch: pytest.MonkeyPatch,
    client: TestClient,
    agent_cfg,
    auth_headers,  # noqa: ARG001
) -> None:
    cfg, cache, audit_path, cursor = agent_cfg
    cfg.server.url = "http://testserver"
    _patch_httpx_to_testclient(monkeypatch, client)

    result = perform_sync(
        config=cfg,
        inventory=_inv(),
        findings=[],
        audit_path=audit_path,
        audit_cursor_path=cursor,
        policy_cache_path=cache,
    )
    assert result.error is None, result.error
    assert result.inventory_posted is True
    assert result.policy_updated is True
    assert result.new_policy_revision == 1
    assert cache.exists()
    # ETag-файл записан.
    assert cache.with_suffix(cache.suffix + ".etag").exists()


def test_sync_uses_etag_on_second_call(
    monkeypatch: pytest.MonkeyPatch,
    client: TestClient,
    agent_cfg,
) -> None:
    cfg, cache, audit_path, cursor = agent_cfg
    cfg.server.url = "http://testserver"
    _patch_httpx_to_testclient(monkeypatch, client)

    perform_sync(cfg, _inv(), [], audit_path, cursor, cache)
    cache_mtime_after_first = cache.stat().st_mtime

    # Гарантируем, что разница в mtime возможна (1с разрешение FS).
    time.sleep(0.05)
    result2 = perform_sync(cfg, _inv(), [], audit_path, cursor, cache)
    assert result2.error is None
    # При If-None-Match=etag и совпадении сервер вернёт 304 → cache не перезаписан.
    assert result2.policy_updated is False
    assert cache.stat().st_mtime == cache_mtime_after_first


def test_sync_sends_only_deny_and_failopen(
    monkeypatch: pytest.MonkeyPatch,
    client: TestClient,
    agent_cfg,
) -> None:
    cfg, cache, audit_path, cursor = agent_cfg
    cfg.server.url = "http://testserver"
    _patch_httpx_to_testclient(monkeypatch, client)

    logger = make_audit_logger(audit_path, 10_000_000, 5)
    # Пишем три записи: allow / deny / fail_open. Только последние две улетят.
    write_audit(
        logger,
        AuditEntry(
            timestamp=datetime.now(UTC),
            tool_name="Bash",
            decision="allow",
            tool_input_fingerprint="aaa",
        ),
    )
    write_audit(
        logger,
        AuditEntry(
            timestamp=datetime.now(UTC),
            tool_name="Bash",
            decision="deny",
            rule_id="commands.denylist",
            tool_input_fingerprint="bbb",
        ),
    )
    write_audit(
        logger,
        AuditEntry(
            timestamp=datetime.now(UTC),
            tool_name="Bash",
            decision="allow",
            fail_open=True,
            tool_input_fingerprint="ccc",
        ),
    )

    result = perform_sync(cfg, _inv(), [], audit_path, cursor, cache)
    assert result.error is None
    assert result.server_response is not None
    assert result.server_response["stored_audit_count"] == 2  # deny + fail_open

    # cursor сдвинулся — повторный sync не отправит те же записи.
    result2 = perform_sync(cfg, _inv(), [], audit_path, cursor, cache)
    assert result2.server_response is not None
    assert result2.server_response["stored_audit_count"] == 0


def test_sync_server_unreachable_does_not_corrupt_cache(
    monkeypatch: pytest.MonkeyPatch,
    client: TestClient,
    agent_cfg,
) -> None:
    """При недоступности сервера cache не трогается, error выставлен."""
    cfg, cache, audit_path, cursor = agent_cfg
    cfg.server.url = "http://unreachable-host-9999"

    # Не патчим httpx → реальная попытка соединиться, упадёт ConnectError.
    # Пишем в cache что-то заведомо валидное, чтобы потом проверить, что не затёрли.
    cache.parent.mkdir(parents=True, exist_ok=True)
    p = Policy(meta=PolicyMeta(revision=7, updated_at=datetime.now(UTC)))
    cache.write_text(yaml.safe_dump(p.model_dump(mode="json"), sort_keys=False))

    result = perform_sync(cfg, _inv(), [], audit_path, cursor, cache, timeout_sec=1.0)
    assert result.error is not None
    assert result.inventory_posted is False
    # Cache остался каким был.
    loaded = yaml.safe_load(cache.read_text())
    assert loaded["meta"]["revision"] == 7
