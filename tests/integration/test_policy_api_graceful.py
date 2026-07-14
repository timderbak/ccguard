"""GET /api/v1/policy must degrade gracefully on a fresh, unconfigured instance.

Before: an empty DB + missing bootstrap file raised an uncaught FileNotFoundError
inside PolicyLoader → 500. The agent polls this endpoint on every sync, so a
fresh non-docker server hard-failed the agent. It must return a graceful 503
('no policy configured yet') instead — matching the web /policy empty-state.
"""
from __future__ import annotations

from pathlib import Path

from ccguard.server.policy_loader import PolicyLoader


def test_api_policy_returns_503_not_500_when_unconfigured(client, auth_headers) -> None:
    # Point the loader at a non-existent bootstrap file with no published policy
    # in the DB → load_with_etag raises FileNotFoundError.
    eng = client.app.state.engine
    client.app.state.policy_loader = PolicyLoader(
        file_path=Path("/nonexistent/policy.yaml"), engine=eng
    )
    r = client.get("/api/v1/policy", headers=auth_headers)
    assert r.status_code == 503, f"expected graceful 503, got {r.status_code}: {r.text[:300]}"


def test_api_policy_still_200_when_configured(client, auth_headers) -> None:
    # Sanity: the normal path (bootstrap file present, from the conftest fixture)
    # still serves the policy.
    r = client.get("/api/v1/policy", headers=auth_headers)
    assert r.status_code == 200, r.text[:300]
