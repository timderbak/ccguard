"""risk.weight.<signal> overrides from SettingsRecord are actually loaded.

The docstring long claimed weights were "overridable via SettingsRecord", but
``evaluate_one`` passed the baked ``DEFAULT_WEIGHTS`` — so calibration required a
redeploy. These guard that the override path is live.
"""
from __future__ import annotations

from fastapi.testclient import TestClient
from sqlmodel import Session

from ccguard.server.services import risk_service
from ccguard.server.services.risk_constants import DEFAULT_WEIGHTS
from ccguard.server.services.settings_service import set_setting

pytestmark = __import__("pytest").mark.integration


def test_no_overrides_returns_defaults(client: TestClient) -> None:
    with Session(client.app.state.engine) as s:  # type: ignore[attr-defined]
        weights = risk_service._load_weights(s)
    assert weights == DEFAULT_WEIGHTS
    assert weights is not DEFAULT_WEIGHTS  # a copy, never the shared default


def test_override_existing_signal_weight(client: TestClient) -> None:
    with Session(client.app.state.engine) as s:  # type: ignore[attr-defined]
        set_setting(s, "risk.weight.cred.read.aws", "9.9")
        weights = risk_service._load_weights(s)
    assert weights["cred.read.aws"] == 9.9
    # untouched signals keep their baked default
    assert weights["egress.network_tool"] == DEFAULT_WEIGHTS["egress.network_tool"]


def test_override_can_weight_a_brand_new_signal(client: TestClient) -> None:
    with Session(client.app.state.engine) as s:  # type: ignore[attr-defined]
        set_setting(s, "risk.weight.custom.new_signal", "7.0")
        weights = risk_service._load_weights(s)
    assert weights["custom.new_signal"] == 7.0


def test_bad_override_value_keeps_default(client: TestClient) -> None:
    with Session(client.app.state.engine) as s:  # type: ignore[attr-defined]
        set_setting(s, "risk.weight.cred.read.aws", "not-a-number")
        weights = risk_service._load_weights(s)
    assert weights["cred.read.aws"] == DEFAULT_WEIGHTS["cred.read.aws"]
