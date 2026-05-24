"""Аутентификация: 401 без токена, 401 с невалидным, 200 с валидным."""

from __future__ import annotations

from fastapi.testclient import TestClient


def test_health_no_auth_required(client: TestClient) -> None:
    r = client.get("/health")
    assert r.status_code == 200
    body = r.json()
    assert body["status"] == "ok"


def test_policy_requires_token(client: TestClient) -> None:
    r = client.get("/api/v1/policy")
    assert r.status_code == 401


def test_policy_rejects_invalid_token(client: TestClient) -> None:
    r = client.get("/api/v1/policy", headers={"X-CCGuard-Token": "wrong"})
    assert r.status_code == 401


def test_policy_accepts_valid_token(client: TestClient, auth_headers: dict[str, str]) -> None:
    r = client.get("/api/v1/policy", headers=auth_headers)
    assert r.status_code == 200
    body = r.json()
    assert body["meta"]["revision"] == 1


def test_machines_requires_token(client: TestClient) -> None:
    r = client.get("/api/v1/machines")
    assert r.status_code == 401


def test_findings_requires_token(client: TestClient) -> None:
    r = client.get("/api/v1/findings")
    assert r.status_code == 401


def test_inventory_post_requires_token(client: TestClient) -> None:
    r = client.post("/api/v1/inventory", json={})
    assert r.status_code == 401


def test_db_token_authenticates_agent(monkeypatch, tmp_path):
    from fastapi.testclient import TestClient
    from sqlmodel import Session

    from ccguard.server.main import create_app
    from ccguard.server.services.token_service import create_token

    monkeypatch.delenv("CCGUARD_TOKENS", raising=False)
    monkeypatch.setenv("CCGUARD_DB_URL", f"sqlite:///{tmp_path}/db.sqlite")
    policy_path = tmp_path / "policy.yaml"
    policy_path.write_text(
        "meta:\n  schema_version: 1\n  revision: 1\n"
        "  updated_at: '2026-01-01T00:00:00Z'\n"
    )
    monkeypatch.setenv("CCGUARD_POLICY_PATH", str(policy_path))

    with TestClient(create_app()) as client:
        with Session(client.app.state.engine) as s:
            raw = create_token(s, label="dev")

        r = client.get("/api/v1/policy", headers={"X-CCGuard-Token": raw})
        assert r.status_code != 401
