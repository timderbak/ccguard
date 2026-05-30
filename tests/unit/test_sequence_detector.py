"""Pure cred→egress sequence detector kernel."""
from __future__ import annotations

from datetime import UTC, datetime, timedelta

from ccguard.server.services.sequence_constants import CRED_PREFIX, EGRESS_PREFIX
from ccguard.server.services.sequence_service import (
    SequenceInputEvent,
    detect_exfil_sequence,
)

WINDOW = 15.0  # minutes


def _now() -> datetime:
    return datetime(2026, 5, 30, 12, 0, 0, tzinfo=UTC)


def _evt(offset_minutes: float, signals: tuple[str, ...]) -> SequenceInputEvent:
    return SequenceInputEvent(ts=_now() + timedelta(minutes=offset_minutes), signals=signals)


def test_empty_returns_none():
    assert detect_exfil_sequence([], WINDOW, CRED_PREFIX, EGRESS_PREFIX) is None


def test_cred_only_returns_none():
    events = [_evt(0, ("cred.read.aws",))]
    assert detect_exfil_sequence(events, WINDOW, CRED_PREFIX, EGRESS_PREFIX) is None


def test_egress_only_returns_none():
    events = [_evt(0, ("egress.network_tool",))]
    assert detect_exfil_sequence(events, WINDOW, CRED_PREFIX, EGRESS_PREFIX) is None


def test_cred_then_egress_within_window_matches():
    events = [_evt(0, ("cred.read.aws",)), _evt(5, ("egress.network_tool",))]
    match = detect_exfil_sequence(events, WINDOW, CRED_PREFIX, EGRESS_PREFIX)
    assert match is not None
    assert match.cred_signal == "cred.read.aws"
    assert match.egress_signal == "egress.network_tool"
    assert match.elapsed_seconds == 300.0


def test_egress_then_cred_reverse_order_returns_none():
    events = [_evt(0, ("egress.network_tool",)), _evt(5, ("cred.read.aws",))]
    assert detect_exfil_sequence(events, WINDOW, CRED_PREFIX, EGRESS_PREFIX) is None


def test_cred_then_egress_beyond_window_returns_none():
    events = [_evt(0, ("cred.read.aws",)), _evt(20, ("egress.network_tool",))]
    assert detect_exfil_sequence(events, WINDOW, CRED_PREFIX, EGRESS_PREFIX) is None


def test_cred_and_egress_same_event_matches_with_zero_gap():
    events = [_evt(0, ("cred.read.aws", "egress.network_tool"))]
    match = detect_exfil_sequence(events, WINDOW, CRED_PREFIX, EGRESS_PREFIX)
    assert match is not None
    assert match.elapsed_seconds == 0.0


def test_unsorted_input_still_detects():
    events = [_evt(5, ("egress.network_tool",)), _evt(0, ("cred.read.aws",))]
    match = detect_exfil_sequence(events, WINDOW, CRED_PREFIX, EGRESS_PREFIX)
    assert match is not None
    assert match.elapsed_seconds == 300.0


def test_first_pairable_cred_wins():
    # Two cred events at 0 and 3; an egress at 7 is in window for both.
    # Earliest cred should be the trigger (smallest elapsed_seconds bound).
    events = [
        _evt(0, ("cred.read.aws",)),
        _evt(3, ("cred.read.ssh",)),
        _evt(7, ("egress.network_tool",)),
    ]
    match = detect_exfil_sequence(events, WINDOW, CRED_PREFIX, EGRESS_PREFIX)
    assert match is not None
    assert match.cred_signal == "cred.read.aws"
    assert match.elapsed_seconds == 7 * 60.0
