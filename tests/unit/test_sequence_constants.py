"""Sequence detector constants are well-formed (Behavioral Detection, Stage 3)."""
from __future__ import annotations

from ccguard.agent.signals.catalog import CATALOG
from ccguard.server.services.sequence_constants import (
    CRED_PREFIX,
    DEFAULT_LOOKBACK_HOURS,
    DEFAULT_WINDOW_MINUTES,
    EGRESS_PREFIX,
    SEQUENCE_RULE_ID,
)


def test_rule_id_is_canonical():
    assert SEQUENCE_RULE_ID == "ioa.exfil_sequence"


def test_tunable_defaults_are_sane():
    assert DEFAULT_WINDOW_MINUTES > 0
    assert DEFAULT_LOOKBACK_HOURS > 0
    # Window must fit inside lookback so the SQL scan covers any matchable pair.
    assert DEFAULT_WINDOW_MINUTES / 60.0 <= DEFAULT_LOOKBACK_HOURS


def test_prefixes_match_catalog_signals():
    ids = {s.id for s in CATALOG}
    assert any(sid.startswith(CRED_PREFIX) for sid in ids), CRED_PREFIX
    assert any(sid.startswith(EGRESS_PREFIX) for sid in ids), EGRESS_PREFIX
