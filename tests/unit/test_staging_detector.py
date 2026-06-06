"""Pure trigger→staging-write[→egress] chain detector kernel (ТЗ-02).

Mirrors test_sequence_detector.py style: the kernel is a pure function over a
list of SequenceInputEvent, no DB. egress is optional — the match is counted on
trigger + staging-write, and egress only raises severity downstream.
"""
from __future__ import annotations

from datetime import UTC, datetime, timedelta

from ccguard.server.services.sequence_constants import (
    EGRESS_PREFIX,
    EXTERNAL_CONTENT_SIGNAL,
    STAGING_HIDDEN_SIGNAL,
    STAGING_NORMAL_SIGNAL,
    STAGING_TRIGGER_PREFIXES,
)
from ccguard.server.services.sequence_service import (
    SequenceInputEvent,
    detect_staging_chain,
)

WINDOW = 15.0


def _now() -> datetime:
    return datetime(2026, 6, 6, 12, 0, 0, tzinfo=UTC)


def _evt(offset_minutes: float, signals: tuple[str, ...]) -> SequenceInputEvent:
    return SequenceInputEvent(ts=_now() + timedelta(minutes=offset_minutes), signals=signals)


def _detect(events):
    return detect_staging_chain(
        events,
        WINDOW,
        trigger_prefixes=STAGING_TRIGGER_PREFIXES,
        hidden_signal=STAGING_HIDDEN_SIGNAL,
        normal_signal=STAGING_NORMAL_SIGNAL,
        egress_prefix=EGRESS_PREFIX,
        external_signal=EXTERNAL_CONTENT_SIGNAL,
    )


def test_empty_returns_none():
    assert _detect([]) is None


def test_trigger_only_returns_none():
    assert _detect([_evt(0, ("cred.read.aws",))]) is None


def test_write_only_returns_none():
    assert _detect([_evt(0, ("fs.write.hidden",))]) is None


def test_trigger_then_hidden_write_matches_without_egress():
    m = _detect([_evt(0, ("cred.read.aws",)), _evt(5, ("fs.write.hidden",))])
    assert m is not None
    assert m.trigger_signal == "cred.read.aws"
    assert m.write_signal == "fs.write.hidden"
    assert m.egress_present is False
    assert m.elapsed_seconds == 300.0


def test_recon_trigger_also_valid():
    m = _detect([_evt(0, ("recon.cloud_metadata",)), _evt(2, ("fs.write.hidden",))])
    assert m is not None
    assert m.trigger_signal == "recon.cloud_metadata"


def test_full_chain_with_egress_sets_flag():
    m = _detect(
        [
            _evt(0, ("cred.read.aws",)),
            _evt(3, ("fs.write.hidden",)),
            _evt(6, ("egress.network_tool",)),
        ]
    )
    assert m is not None
    assert m.egress_present is True
    assert m.egress_signal == "egress.network_tool"


def test_normal_write_matches_as_weaker():
    m = _detect([_evt(0, ("cred.read.aws",)), _evt(4, ("fs.write.normal",))])
    assert m is not None
    assert m.write_signal == "fs.write.normal"
    assert m.egress_present is False


def test_hidden_preferred_over_normal_in_window():
    m = _detect(
        [
            _evt(0, ("cred.read.aws",)),
            _evt(2, ("fs.write.normal",)),
            _evt(4, ("fs.write.hidden",)),
        ]
    )
    assert m is not None
    assert m.write_signal == "fs.write.hidden"


def test_write_beyond_window_returns_none():
    assert _detect([_evt(0, ("cred.read.aws",)), _evt(20, ("fs.write.hidden",))]) is None


def test_write_before_trigger_returns_none():
    assert _detect([_evt(0, ("fs.write.hidden",)), _evt(5, ("cred.read.aws",))]) is None


def test_egress_before_write_not_counted():
    """An egress that precedes the staging write is not part of this chain."""
    m = _detect(
        [
            _evt(0, ("cred.read.aws",)),
            _evt(2, ("egress.network_tool",)),
            _evt(4, ("fs.write.hidden",)),
        ]
    )
    assert m is not None
    assert m.egress_present is False


def test_egress_beyond_window_after_write_not_counted():
    m = _detect(
        [
            _evt(0, ("cred.read.aws",)),
            _evt(2, ("fs.write.hidden",)),
            _evt(30, ("egress.network_tool",)),
        ]
    )
    assert m is not None
    assert m.egress_present is False


# --- external_trigger flag (ТЗ-03) ------------------------------------------


def test_external_read_is_valid_trigger_and_flags_external():
    m = _detect(
        [_evt(0, ("content.read.external",)), _evt(3, ("fs.write.hidden",))]
    )
    assert m is not None
    assert m.external_trigger is True


def test_non_external_trigger_flag_false():
    m = _detect([_evt(0, ("cred.read.aws",)), _evt(3, ("fs.write.hidden",))])
    assert m is not None
    assert m.external_trigger is False


def test_external_signal_on_trigger_event_alongside_cred():
    """Trigger event carrying both cred-read and external → external_trigger."""
    m = _detect(
        [
            _evt(0, ("cred.read.aws", "content.read.external")),
            _evt(3, ("fs.write.hidden",)),
        ]
    )
    assert m is not None
    assert m.external_trigger is True
