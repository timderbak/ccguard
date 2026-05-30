"""Risk weight table covers the Stage 1 catalog and parses cleanly."""
from __future__ import annotations

from ccguard.agent.signals.catalog import CATALOG
from ccguard.server.services.risk_constants import (
    DEFAULT_HALF_LIFE_HOURS,
    DEFAULT_THRESHOLD,
    DEFAULT_WEIGHTS,
    DEFAULT_WINDOW_HOURS,
    RISK_RULE_ID,
)


def test_every_catalog_signal_has_a_weight():
    catalog_ids = {s.id for s in CATALOG}
    weight_ids = set(DEFAULT_WEIGHTS.keys())
    assert catalog_ids <= weight_ids, f"missing weights for: {catalog_ids - weight_ids}"


def test_weights_are_positive_floats():
    for sid, w in DEFAULT_WEIGHTS.items():
        assert isinstance(w, float), sid
        assert w > 0, sid


def test_tunable_defaults_are_sane():
    assert DEFAULT_THRESHOLD > 0
    assert DEFAULT_WINDOW_HOURS > 0
    assert DEFAULT_HALF_LIFE_HOURS > 0
    assert RISK_RULE_ID == "risk.elevated"
