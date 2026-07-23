"""Pure toxic-flow (confused-deputy) detector kernel.

Mirrors test_staging_detector.py style: a pure function over a list of
SequenceInputEvent, no DB. The flow is taint (external/untrusted content) →
weaponized sink (config self-tamper / persistence / destruction / suspicious-host
exfil), the sink STRICTLY LATER than the taint. Generic egress is excluded by
design (the taint marker fires on every MCP call), so precision stays high.
"""
from __future__ import annotations

from datetime import UTC, datetime, timedelta

from ccguard.server.services.sequence_constants import (
    CONFIG_TAMPER_SINK,
    TAINT_SOURCE_SIGNAL,
    TOXIC_SINK_EXACT,
    TOXIC_SINK_PREFIXES,
)
from ccguard.server.services.sequence_service import (
    SequenceInputEvent,
    detect_toxic_flow,
)

WINDOW = 15.0
TAINT = TAINT_SOURCE_SIGNAL  # "content.read.external"


def _now() -> datetime:
    return datetime(2026, 6, 6, 12, 0, 0, tzinfo=UTC)


def _evt(offset_minutes: float, signals: tuple[str, ...]) -> SequenceInputEvent:
    return SequenceInputEvent(ts=_now() + timedelta(minutes=offset_minutes), signals=signals)


def _detect(events):
    return detect_toxic_flow(
        events,
        WINDOW,
        taint_signal=TAINT,
        sink_exact=TOXIC_SINK_EXACT,
        sink_prefixes=TOXIC_SINK_PREFIXES,
        config_tamper_sink=CONFIG_TAMPER_SINK,
    )


# --- negatives -------------------------------------------------------------


def test_empty_returns_none():
    assert _detect([]) is None


def test_taint_only_returns_none():
    assert _detect([_evt(0, (TAINT,))]) is None


def test_sink_only_returns_none():
    assert _detect([_evt(0, ("config.agent_settings_edit",))]) is None


def test_generic_egress_is_not_a_sink():
    """KEY precision guard: because the taint marker fires on EVERY mcp__* call,
    an external read followed by an ordinary WebFetch/curl (egress.http_client /
    egress.network_tool) must NOT trip toxic_flow."""
    assert _detect([_evt(0, (TAINT,)), _evt(1, ("egress.http_client",))]) is None
    assert _detect([_evt(0, (TAINT,)), _evt(1, ("egress.network_tool",))]) is None


def test_sink_before_taint_returns_none():
    # order matters — the external content must PRECEDE the weaponized action
    assert _detect([_evt(0, ("persist.cron",)), _evt(1, (TAINT,))]) is None


def test_sink_out_of_window_returns_none():
    assert _detect([_evt(0, (TAINT,)), _evt(WINDOW + 0.1, ("impact.delete",))]) is None


def test_same_event_taint_and_sink_is_not_a_flow():
    # a single event carrying both is not a flow (sink must be a later event)
    assert _detect([_evt(0, (TAINT, "persist.cron"))]) is None


# --- positives + sink classification ---------------------------------------


def test_config_tamper_sink_matches():
    m = _detect([_evt(0, (TAINT,)), _evt(2, ("config.agent_settings_edit",))])
    assert m is not None
    assert m.sink_class == "config_tamper"
    assert m.sink_signal == "config.agent_settings_edit"
    assert m.elapsed_seconds == 120.0


def test_persistence_sink_matches():
    m = _detect([_evt(0, (TAINT,)), _evt(1, ("persist.ssh_authorized_keys",))])
    assert m is not None
    assert m.sink_class == "persistence"


def test_destructive_sink_matches():
    m = _detect([_evt(0, (TAINT,)), _evt(3, ("impact.disk_wipe",))])
    assert m is not None
    assert m.sink_class == "destructive"


def test_suspicious_egress_sink_matches():
    m = _detect([_evt(0, (TAINT,)), _evt(1, ("egress.paste_site",))])
    assert m is not None
    assert m.sink_class == "exfil"


def test_window_boundary_inclusive():
    m = _detect([_evt(0, (TAINT,)), _evt(WINDOW, ("persist.cron",))])
    assert m is not None
    assert m.elapsed_seconds == WINDOW * 60.0


def test_zero_gap_distinct_events_match():
    # taint and sink at the same instant but distinct events → flow (gap 0)
    m = _detect([_evt(0, (TAINT,)), _evt(0, ("impact.delete",))])
    assert m is not None
    assert m.elapsed_seconds == 0.0


def test_earliest_taint_and_first_sink_win():
    events = [
        _evt(0, (TAINT,)),
        _evt(1, ("n",)),
        _evt(2, ("persist.cron",)),   # first qualifying sink after the taint
        _evt(5, ("impact.delete",)),
    ]
    m = _detect(events)
    assert m is not None
    assert m.taint_ts == _now()
    assert m.sink_signal == "persist.cron"
    assert m.elapsed_seconds == 120.0
