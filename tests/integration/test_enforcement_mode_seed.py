"""Server-side enforcement_mode foundation (Behavioral Detection, Stage 5).

Default mode is ``observe`` — closes the explicit "remove all blocking" ask.
Agent-side honoring of the mode is a separate change.
"""
from __future__ import annotations

from fastapi.testclient import TestClient
from sqlmodel import Session

from ccguard.server.services.settings_service import (
    get_enforcement_mode,
    get_setting,
    seed_enforcement_mode,
    set_setting,
)


def test_default_mode_is_observe(client: TestClient) -> None:
    with Session(client.app.state.engine) as session:  # type: ignore[attr-defined]
        seed_enforcement_mode(session)
        assert get_setting(session, "enforcement_mode") == "observe"
        assert get_enforcement_mode(session) == "observe"


def test_admin_can_switch_to_enforce(client: TestClient) -> None:
    with Session(client.app.state.engine) as session:  # type: ignore[attr-defined]
        seed_enforcement_mode(session)
        set_setting(session, "enforcement_mode", "enforce")
        assert get_enforcement_mode(session) == "enforce"


def test_corrupt_value_falls_back_to_observe(client: TestClient) -> None:
    with Session(client.app.state.engine) as session:  # type: ignore[attr-defined]
        seed_enforcement_mode(session)
        set_setting(session, "enforcement_mode", "bogus")
        assert get_enforcement_mode(session) == "observe"


def test_seed_preserves_admin_edits(client: TestClient) -> None:
    with Session(client.app.state.engine) as session:  # type: ignore[attr-defined]
        seed_enforcement_mode(session)
        set_setting(session, "enforcement_mode", "enforce")
        seed_enforcement_mode(session)
        assert get_setting(session, "enforcement_mode") == "enforce"
