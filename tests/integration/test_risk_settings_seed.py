"""Risk settings are seeded on first startup and preserved on re-seed."""
from __future__ import annotations

from fastapi.testclient import TestClient
from sqlmodel import Session

from ccguard.server.services.settings_service import (
    get_setting,
    seed_risk_settings,
    set_setting,
)


def test_seed_writes_defaults(client: TestClient) -> None:
    with Session(client.app.state.engine) as session:  # type: ignore[attr-defined]
        seed_risk_settings(session)
        assert get_setting(session, "risk.threshold") is not None
        assert get_setting(session, "risk.window_hours") is not None
        assert get_setting(session, "risk.half_life_hours") is not None


def test_seed_preserves_admin_edits(client: TestClient) -> None:
    with Session(client.app.state.engine) as session:  # type: ignore[attr-defined]
        seed_risk_settings(session)
        set_setting(session, "risk.threshold", "42.0")
        seed_risk_settings(session)
        assert get_setting(session, "risk.threshold") == "42.0"
