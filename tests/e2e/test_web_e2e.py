"""E2E smoke: web UI works end-to-end through Docker compose.

Requires `docker compose up -d server` to be running.
"""

from __future__ import annotations

import os

import httpx
import pytest

BASE_URL = os.environ.get("CCGUARD_E2E_URL", "http://localhost:8080")


@pytest.mark.e2e
def test_web_login_and_overview() -> None:
    with httpx.Client(base_url=BASE_URL, follow_redirects=False) as client:
        r = client.get("/", headers={"accept": "text/html"})
        assert r.status_code in (302, 303, 307)

        r = client.post("/login", data={"username": "admin", "password": "admin"})
        assert r.status_code == 303
        sid = r.cookies["ccg_session"]

        r = client.get("/", cookies={"ccg_session": sid})
        assert r.status_code == 200
        assert "Overview" in r.text

        r = client.get("/_partials/overview/fleet-table", cookies={"ccg_session": sid})
        assert r.status_code == 200
