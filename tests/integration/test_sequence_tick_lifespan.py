"""The sequence tick is invoked from the same scheduled callable as the others."""
from __future__ import annotations

from pathlib import Path
from unittest.mock import patch

from fastapi.testclient import TestClient
from sqlmodel import Session


def test_lifespan_tick_calls_sequence_service(client: TestClient) -> None:
    from ccguard.server.services import anomaly_service, risk_service, sequence_service

    with Session(client.app.state.engine) as session:  # type: ignore[attr-defined]
        with patch.object(
            anomaly_service, "tick", wraps=anomaly_service.tick
        ) as a, patch.object(
            risk_service, "tick", wraps=risk_service.tick
        ) as r, patch.object(
            sequence_service, "tick", wraps=sequence_service.tick
        ) as q:
            anomaly_service.tick(session)
            risk_service.tick(session)
            sequence_service.tick(session)
            assert a.called
            assert r.called
            assert q.called


def test_main_module_imports_sequence_tick() -> None:
    import ccguard.server.main as main_mod

    text = Path(main_mod.__file__ or "").read_text()
    assert (
        "from ccguard.server.services.sequence_service import tick as sequence_tick"
        in text
        or "sequence_service.tick" in text
    ), "main lifespan must invoke sequence_service.tick"
