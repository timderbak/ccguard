"""The risk tick is invoked from the same scheduled callable as the anomaly tick."""
from __future__ import annotations

from pathlib import Path

from fastapi.testclient import TestClient
from sqlmodel import Session

from ccguard.server.services import anomaly_service, risk_service


def test_both_ticks_composable_on_empty_db(client: TestClient) -> None:
    """Smoke: anomaly and risk ticks share a Session and don't step on each other."""
    with Session(client.app.state.engine) as session:  # type: ignore[attr-defined]
        a = anomaly_service.tick(session)
        r = risk_service.tick(session)
    assert a["findings_emitted"] == 0
    assert r["findings_emitted"] == 0


def test_main_module_invokes_risk_tick() -> None:
    """Static guard: ``main`` must reference ``risk_service.tick`` so the
    lifespan chains it. Catches a refactor that drops the wiring."""
    import ccguard.server.main as main_mod

    src_path = main_mod.__file__ or ""
    assert src_path, "main module has no __file__"
    text = Path(src_path).read_text()
    assert "risk_tick" in text or "risk_service.tick" in text, (
        "main lifespan must invoke risk_service.tick"
    )
