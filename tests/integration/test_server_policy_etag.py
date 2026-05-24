"""ETag-кэширование политики: 200 при первом, 304 при If-None-Match, 200 после изменения."""

from __future__ import annotations

from datetime import UTC, datetime

import yaml
from fastapi.testclient import TestClient
from sqlmodel import Session

from ccguard.schemas import Policy, PolicyMeta
from ccguard.server.services.policy_service import publish_draft, save_draft


def test_policy_returns_200_with_etag(client: TestClient, auth_headers: dict[str, str]) -> None:
    r = client.get("/api/v1/policy", headers=auth_headers)
    assert r.status_code == 200
    assert r.headers.get("ETag") == '"rev-1"'


def test_policy_returns_304_when_matching_etag(
    client: TestClient, auth_headers: dict[str, str]
) -> None:
    r1 = client.get("/api/v1/policy", headers=auth_headers)
    etag = r1.headers["ETag"]

    r2 = client.get(
        "/api/v1/policy", headers={**auth_headers, "If-None-Match": etag}
    )
    assert r2.status_code == 304
    assert r2.headers.get("ETag") == etag
    assert r2.content == b""


def test_policy_returns_200_when_revision_increases(
    client: TestClient, auth_headers: dict[str, str]
) -> None:
    r1 = client.get("/api/v1/policy", headers=auth_headers)
    old_etag = r1.headers["ETag"]
    assert old_etag == '"rev-1"'

    # Publish revision 2 via policy_service (DB-backed).
    new_policy = Policy(meta=PolicyMeta(revision=2, updated_at=datetime.now(UTC)))
    new_yaml = yaml.safe_dump(new_policy.model_dump(mode="json"), sort_keys=False)
    engine = client.app.state.engine  # type: ignore[attr-defined]
    with Session(engine) as session:
        save_draft(session, yaml_text=new_yaml, user_id="test")
        publish_draft(session, user_id="test")

    r2 = client.get(
        "/api/v1/policy", headers={**auth_headers, "If-None-Match": old_etag}
    )
    assert r2.status_code == 200
    assert r2.headers["ETag"] == '"rev-2"'
    assert r2.json()["meta"]["revision"] == 2
