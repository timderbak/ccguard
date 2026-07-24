"""IOC host-feed auto-collection (Path-2 · abuse.ch) — offline, injected feeds.

Covers the two halves: the Feodo CSV parser (pure, no network) and the
``run_ioc_feeds`` orchestrator (touches a temp DB). The headline invariant: a
fetched IOC lands ``status="pending"`` and is NOT served to the policy until an
admin flips it active.
"""
from __future__ import annotations

from datetime import UTC, datetime, timedelta

from sqlmodel import Session, select

from ccguard.server.db.models import ThreatIndicator
from ccguard.server.db.session import init_db, make_engine
from ccguard.server.services.indicator_override_service import load_suspicious_host_rules
from ccguard.server.services.ioc_feed_service import (
    FeodoTrackerFeed,
    HostIOC,
    run_ioc_feeds,
    should_run,
)
from ccguard.server.services.settings_service import set_setting

# A representative slice of the abuse.ch Feodo ipblocklist.csv (comment header +
# rows). Columns: first_seen_utc,dst_ip,dst_port,c2_status,last_online,malware
_FEODO_CSV = (
    "# Feodo Tracker IP Blocklist (CC0)\n"
    "# first_seen_utc,dst_ip,dst_port,c2_status,last_online,malware\n"
    '"2026-01-02 10:00:00","185.220.101.5","443","online","2026-07-20","Dridex"\n'
    '"2026-01-03 11:00:00","91.240.118.172","8080","online","2026-07-21","Emotet"\n'
    '"2026-01-04 12:00:00","2001:db8::1","443","online","2026-07-22","QakBot"\n'
)


def _engine(tmp_path):
    eng = make_engine(f"sqlite:///{tmp_path}/ioc.db")
    init_db(eng)
    return eng


class _FakeFeed:
    """A feed that emits a fixed list (or raises), for orchestrator tests."""

    def __init__(self, name, iocs=None, raise_exc=None):
        self.name = name
        self._iocs = iocs or []
        self._raise = raise_exc

    def poll(self):
        if self._raise is not None:
            raise self._raise
        return list(self._iocs)


def _ioc(value, source="abuse.ch-feodo"):
    return HostIOC(
        value=value,
        source=source,
        source_ref="test",
        technique="T1071.001",
        tactic="command-and-control",
        weight=4.0,
        description="test C2 IP",
    )


# --- Feodo CSV parser (no network) ------------------------------------------


def test_feodo_parses_ips_skips_comments():
    feed = FeodoTrackerFeed(fetch=lambda: _FEODO_CSV)
    iocs = feed.poll()
    values = {i.value for i in iocs}
    assert values == {"185.220.101.5", "91.240.118.172", "2001:db8::1"}
    # malware family threaded into the description
    dridex = next(i for i in iocs if i.value == "185.220.101.5")
    assert "Dridex" in dridex.description
    assert dridex.source == "abuse.ch-feodo"
    assert dridex.tactic == "command-and-control"


def test_feodo_skips_non_ip_and_malformed_lines():
    csv = (
        "# header\n"
        '"2026-01-02","not-an-ip","443","online","x","Dridex"\n'
        "malformed-single-column\n"
        '"2026-01-02","10.0.0.1","443","online","x","Emotet"\n'
    )
    feed = FeodoTrackerFeed(fetch=lambda: csv)
    assert {i.value for i in feed.poll()} == {"10.0.0.1"}


def test_feodo_dedups_within_feed():
    csv = (
        '"2026-01-02","1.2.3.4","443","online","x","Dridex"\n'
        '"2026-01-03","1.2.3.4","8080","online","y","Dridex"\n'
    )
    feed = FeodoTrackerFeed(fetch=lambda: csv)
    assert [i.value for i in feed.poll()] == ["1.2.3.4"]


def test_feodo_fetch_error_yields_empty():
    def _boom():
        raise OSError("network down")

    assert FeodoTrackerFeed(fetch=_boom).poll() == []


# --- orchestrator: run_ioc_feeds --------------------------------------------


def test_run_inserts_pending_suspicious_host(tmp_path):
    eng = _engine(tmp_path)
    with Session(eng) as s:
        summary = run_ioc_feeds(s, feeds=[FeodoTrackerFeed(fetch=lambda: _FEODO_CSV)])
        rows = s.exec(
            select(ThreatIndicator).where(ThreatIndicator.source == "abuse.ch-feodo")
        ).all()
    assert summary["inserted"] == 3
    assert len(rows) == 3
    assert all(r.indicator_type == "suspicious_host" for r in rows)
    assert all(r.value_kind == "exact" for r in rows)
    assert all(r.status == "pending" for r in rows)  # human-gated, never auto-live


def test_run_is_idempotent(tmp_path):
    eng = _engine(tmp_path)
    feed = FeodoTrackerFeed(fetch=lambda: _FEODO_CSV)
    with Session(eng) as s:
        first = run_ioc_feeds(s, feeds=[feed])
        second = run_ioc_feeds(s, feeds=[feed])
        total = len(
            s.exec(
                select(ThreatIndicator).where(
                    ThreatIndicator.source == "abuse.ch-feodo"
                )
            ).all()
        )
    assert first["inserted"] == 3
    assert second["inserted"] == 0
    assert second["deduped"] == 3
    assert total == 3


def test_pending_iocs_not_served_until_active(tmp_path):
    eng = _engine(tmp_path)
    with Session(eng) as s:
        run_ioc_feeds(s, feeds=[FeodoTrackerFeed(fetch=lambda: _FEODO_CSV)])
        # pending → the policy host-rule loader must NOT serve them yet
        assert load_suspicious_host_rules(s) == []
        # admin approves one → it becomes a served warn-tier host rule
        row = s.exec(
            select(ThreatIndicator).where(ThreatIndicator.source == "abuse.ch-feodo")
        ).first()
        row.status = "active"
        s.add(row)
        s.commit()
        served = load_suspicious_host_rules(s)
    assert len(served) == 1
    assert served[0]["severity"] == "warn"
    assert row.value in served[0]["pattern"]


def test_feed_isolation_one_bad_one_good(tmp_path):
    eng = _engine(tmp_path)
    good = _FakeFeed("good", iocs=[_ioc("203.0.113.7", source="good")])
    bad = _FakeFeed("bad", raise_exc=RuntimeError("kaboom"))
    with Session(eng) as s:
        summary = run_ioc_feeds(s, feeds=[bad, good])
        rows = s.exec(
            select(ThreatIndicator).where(ThreatIndicator.source == "good")
        ).all()
    assert summary["inserted"] == 1
    assert "bad" in summary["feed_errors"]
    assert len(rows) == 1


def test_invalid_host_value_skipped(tmp_path):
    eng = _engine(tmp_path)
    feed = _FakeFeed("f", iocs=[_ioc("has space", source="f"), _ioc("198.51.100.9", source="f")])
    with Session(eng) as s:
        summary = run_ioc_feeds(s, feeds=[feed])
        rows = s.exec(select(ThreatIndicator).where(ThreatIndicator.source == "f")).all()
    assert summary["inserted"] == 1
    assert summary["invalid"] == 1
    assert [r.value for r in rows] == ["198.51.100.9"]


def test_max_per_feed_cap(tmp_path):
    eng = _engine(tmp_path)
    iocs = [_ioc(f"192.0.2.{n}", source="big") for n in range(1, 20)]
    feed = _FakeFeed("big", iocs=iocs)
    with Session(eng) as s:
        summary = run_ioc_feeds(s, feeds=[feed], max_per_feed=5)
        rows = s.exec(select(ThreatIndicator).where(ThreatIndicator.source == "big")).all()
    assert summary["inserted"] == 5
    assert len(rows) == 5


def test_cross_source_corroboration_allowed(tmp_path):
    # The SAME IP from a DIFFERENT source is a distinct row (cross-corroboration),
    # not a dedup — the composite-unique key includes source.
    eng = _engine(tmp_path)
    with Session(eng) as s:
        run_ioc_feeds(s, feeds=[_FakeFeed("a", iocs=[_ioc("1.1.1.1", source="feed-a")])])
        run_ioc_feeds(s, feeds=[_FakeFeed("b", iocs=[_ioc("1.1.1.1", source="feed-b")])])
        rows = s.exec(
            select(ThreatIndicator).where(ThreatIndicator.value == "1.1.1.1")
        ).all()
    assert {r.source for r in rows} == {"feed-a", "feed-b"}


# --- daily gate --------------------------------------------------------------


def test_should_run_gate(tmp_path):
    eng = _engine(tmp_path)
    now = datetime(2026, 7, 24, 12, 0, tzinfo=UTC)
    with Session(eng) as s:
        assert should_run(s, now=now) is True  # never run → go
        set_setting(s, "ioc_feed.last_run_at", now.isoformat())
        assert should_run(s, now=now + timedelta(hours=1)) is False  # too soon
        assert should_run(s, now=now + timedelta(hours=24)) is True  # a day later
