"""P7-depth: behavioral-volume + signal-rate anomaly aggregators."""
from __future__ import annotations

import json
from datetime import UTC, date, datetime

from sqlmodel import Session

from ccguard.server.db.models import ToolUseEvent
from ccguard.server.db.session import init_db, make_engine
from ccguard.server.services.metric_aggregators import (
    cred_signals_per_day_series,
    egress_signals_per_day_series,
    mcp_calls_per_day_series,
    reads_per_day_series,
    webfetch_per_day_series,
    writes_per_day_series,
)

_ANCHOR = date(2026, 6, 12)


def _engine():
    eng = make_engine("sqlite://")
    init_db(eng)
    return eng


def _seed(
    s: Session,
    *,
    d: date,
    tool_name: str,
    signals: list[str] | None = None,
    machine_id: str = "m1",
) -> None:
    s.add(
        ToolUseEvent(
            machine_id=machine_id,
            ts=datetime(d.year, d.month, d.day, 12, 0, tzinfo=UTC),
            tool_name=tool_name,
            fingerprint="0123456789abcdef",
            decision="allow",
            result_status="success",
            signals_json=json.dumps(signals or []),
        )
    )


def _count_on(series, d: date) -> int:
    return dict(series)[d]


def test_reads_counts_only_read_tool():
    with Session(_engine()) as s:
        _seed(s, d=_ANCHOR, tool_name="Read")
        _seed(s, d=_ANCHOR, tool_name="Read")
        _seed(s, d=_ANCHOR, tool_name="Bash")  # not a read
        s.commit()
        series = reads_per_day_series(s, "m1", _ANCHOR)
    assert len(series) == 14
    assert _count_on(series, _ANCHOR) == 2


def test_writes_counts_write_edit_multiedit():
    with Session(_engine()) as s:
        for tn in ("Write", "Edit", "MultiEdit", "Read"):
            _seed(s, d=_ANCHOR, tool_name=tn)
        s.commit()
        series = writes_per_day_series(s, "m1", _ANCHOR)
    assert _count_on(series, _ANCHOR) == 3  # Read excluded


def test_webfetch_counts_webfetch_and_websearch():
    with Session(_engine()) as s:
        _seed(s, d=_ANCHOR, tool_name="WebFetch")
        _seed(s, d=_ANCHOR, tool_name="WebSearch")
        _seed(s, d=_ANCHOR, tool_name="Bash")
        s.commit()
        series = webfetch_per_day_series(s, "m1", _ANCHOR)
    assert _count_on(series, _ANCHOR) == 2


def test_mcp_calls_match_mcp_prefix_only():
    with Session(_engine()) as s:
        _seed(s, d=_ANCHOR, tool_name="mcp__github__search")
        _seed(s, d=_ANCHOR, tool_name="mcp__fs__read")
        _seed(s, d=_ANCHOR, tool_name="mcpfoo")  # underscore is escaped → no match
        _seed(s, d=_ANCHOR, tool_name="Bash")
        s.commit()
        series = mcp_calls_per_day_series(s, "m1", _ANCHOR)
    assert _count_on(series, _ANCHOR) == 2


def test_egress_signal_rate_counts_egress_events():
    with Session(_engine()) as s:
        _seed(s, d=_ANCHOR, tool_name="Bash", signals=["egress.http_client"])
        _seed(s, d=_ANCHOR, tool_name="Bash", signals=["cred.read.aws", "egress.cloud_cli"])
        _seed(s, d=_ANCHOR, tool_name="Bash", signals=["exec.eval"])  # no egress
        s.commit()
        series = egress_signals_per_day_series(s, "m1", _ANCHOR)
    assert _count_on(series, _ANCHOR) == 2


def test_cred_signal_rate_counts_cred_read_events():
    with Session(_engine()) as s:
        _seed(s, d=_ANCHOR, tool_name="Bash", signals=["cred.read.aws"])
        _seed(s, d=_ANCHOR, tool_name="Bash", signals=["cred.read.saas_token"])
        _seed(s, d=_ANCHOR, tool_name="Bash", signals=["egress.http_client"])  # no cred
        s.commit()
        series = cred_signals_per_day_series(s, "m1", _ANCHOR)
    assert _count_on(series, _ANCHOR) == 2


def test_series_zero_pads_quiet_days():
    with Session(_engine()) as s:
        _seed(s, d=_ANCHOR, tool_name="Read")
        s.commit()
        series = reads_per_day_series(s, "m1", _ANCHOR)
    # 14 days, only the anchor has activity
    assert len(series) == 14
    assert sum(c for _d, c in series) == 1
    assert series[-1] == (_ANCHOR, 1)


def test_other_machine_not_counted():
    with Session(_engine()) as s:
        _seed(s, d=_ANCHOR, tool_name="Read", machine_id="m2")
        s.commit()
        series = reads_per_day_series(s, "m1", _ANCHOR)
    assert sum(c for _d, c in series) == 0
