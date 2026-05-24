"""Smoke test: web routes exist and serve HTML."""

from __future__ import annotations

from fastapi.testclient import TestClient

from ccguard.server.main import create_app


def test_login_page_renders() -> None:
    app = create_app()
    client = TestClient(app)
    r = client.get("/login")
    assert r.status_code == 200
    assert "text/html" in r.headers["content-type"]
    assert "ccguard" in r.text.lower()
