"""ETag-кэширование политики: 200 при первом, 304 при If-None-Match, 200 после изменения."""

from __future__ import annotations

import time
from datetime import UTC, datetime
from pathlib import Path

import yaml
from fastapi.testclient import TestClient

from ccguard.schemas import Policy, PolicyMeta


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
    client: TestClient, auth_headers: dict[str, str], policy_file: Path
) -> None:
    r1 = client.get("/api/v1/policy", headers=auth_headers)
    old_etag = r1.headers["ETag"]
    assert old_etag == '"rev-1"'

    # Пишем новую policy с revision=2; ждём 1.1с чтобы mtime гарантированно изменился.
    time.sleep(1.1)
    new_policy = Policy(meta=PolicyMeta(revision=2, updated_at=datetime.now(UTC)))
    policy_file.write_text(yaml.safe_dump(new_policy.model_dump(mode="json"), sort_keys=False))

    r2 = client.get(
        "/api/v1/policy", headers={**auth_headers, "If-None-Match": old_etag}
    )
    assert r2.status_code == 200
    assert r2.headers["ETag"] == '"rev-2"'
    assert r2.json()["meta"]["revision"] == 2
