"""Sequence settings are seeded on first startup and preserved across re-seed."""
from __future__ import annotations

from fastapi.testclient import TestClient
from sqlmodel import Session

from ccguard.server.services.settings_service import (
    get_setting,
    seed_sequence_settings,
    set_setting,
)


def test_seed_writes_defaults(client: TestClient) -> None:
    with Session(client.app.state.engine) as session:  # type: ignore[attr-defined]
        seed_sequence_settings(session)
        assert get_setting(session, "sequence.window_minutes") is not None
        assert get_setting(session, "sequence.lookback_hours") is not None


def test_seed_preserves_admin_edits(client: TestClient) -> None:
    with Session(client.app.state.engine) as session:  # type: ignore[attr-defined]
        seed_sequence_settings(session)
        set_setting(session, "sequence.window_minutes", "7.5")
        seed_sequence_settings(session)
        assert get_setting(session, "sequence.window_minutes") == "7.5"
