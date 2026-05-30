"""Pure scoring kernel: deterministic, decay-correct, weights honored."""
from __future__ import annotations

import math
from datetime import UTC, datetime, timedelta

from ccguard.server.services.risk_constants import DEFAULT_WEIGHTS
from ccguard.server.services.risk_service import RiskInputEvent, compute_risk_score


def _now() -> datetime:
    return datetime(2026, 5, 30, 12, 0, 0, tzinfo=UTC)


def test_no_events_score_zero():
    br = compute_risk_score([], _now(), DEFAULT_WEIGHTS, 24.0, 6.0)
    assert br.score == 0.0
    assert br.contributions == {}
    assert br.event_count == 0


def test_single_event_now_has_full_weight():
    evt = RiskInputEvent(ts=_now(), signals=("cred.read.aws",))
    br = compute_risk_score([evt], _now(), DEFAULT_WEIGHTS, 24.0, 6.0)
    assert br.score == DEFAULT_WEIGHTS["cred.read.aws"]
    assert br.contributions == {"cred.read.aws": DEFAULT_WEIGHTS["cred.read.aws"]}
    assert br.event_count == 1


def test_event_one_half_life_old_decays_by_half():
    half_life = 6.0
    evt = RiskInputEvent(ts=_now() - timedelta(hours=half_life), signals=("cred.read.aws",))
    br = compute_risk_score([evt], _now(), DEFAULT_WEIGHTS, 24.0, half_life)
    expected = DEFAULT_WEIGHTS["cred.read.aws"] * 0.5
    assert math.isclose(br.score, expected, rel_tol=1e-9)


def test_events_outside_window_are_dropped():
    old = RiskInputEvent(ts=_now() - timedelta(hours=48), signals=("cred.read.aws",))
    br = compute_risk_score([old], _now(), DEFAULT_WEIGHTS, 24.0, 6.0)
    assert br.score == 0.0
    assert br.event_count == 0


def test_multiple_signals_per_event_sum():
    evt = RiskInputEvent(ts=_now(), signals=("cred.read.aws", "egress.network_tool"))
    br = compute_risk_score([evt], _now(), DEFAULT_WEIGHTS, 24.0, 6.0)
    expected = DEFAULT_WEIGHTS["cred.read.aws"] + DEFAULT_WEIGHTS["egress.network_tool"]
    assert math.isclose(br.score, expected, rel_tol=1e-9)


def test_unknown_signal_id_uses_default_weight_one():
    evt = RiskInputEvent(ts=_now(), signals=("future.signal.id",))
    br = compute_risk_score([evt], _now(), DEFAULT_WEIGHTS, 24.0, 6.0)
    assert br.score == 1.0
    assert br.contributions == {"future.signal.id": 1.0}


def test_contributions_aggregate_across_events():
    e1 = RiskInputEvent(ts=_now(), signals=("cred.read.aws",))
    e2 = RiskInputEvent(ts=_now(), signals=("cred.read.aws",))
    br = compute_risk_score([e1, e2], _now(), DEFAULT_WEIGHTS, 24.0, 6.0)
    assert br.contributions["cred.read.aws"] == 2.0 * DEFAULT_WEIGHTS["cred.read.aws"]
    assert br.event_count == 2
