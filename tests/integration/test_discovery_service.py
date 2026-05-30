"""Discovery service: dedup, budget propagation, isolation between monitors."""
from __future__ import annotations

import json
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta

import pytest
from fastapi.testclient import TestClient
from sqlmodel import Session, select

from ccguard.server.db.models import ProposedSignal, SourceFetchLog
from ccguard.server.services import discovery_service
from ccguard.server.services.settings_service import (
    get_setting,
    set_setting,
)
from ccguard.server.services.source_monitors.base import SourceItem


_VALID_DRAFT = {
    "id": "cred.read.session_cookie",
    "attack_technique": "T1539",
    "pattern": r"cookies\.binarycookies",
    "description": "x",
}


@dataclass
class FakeMonitor:
    name: str
    items: list[SourceItem] = field(default_factory=list)
    raises: Exception | None = None

    def poll(self, since: datetime) -> list[SourceItem]:
        if self.raises is not None:
            raise self.raises
        return list(self.items)


@dataclass
class FakeDrafter:
    response: str
    calls: int = 0

    def draft(self, threat_text: str) -> str:
        self.calls += 1
        return self.response


def _mk_item(url: str, title: str = "t") -> SourceItem:
    return SourceItem(
        url=url, title=title, text=f"text for {url}", published_at=datetime.now(UTC)
    )


def test_first_run_drafts_each_item_once(client: TestClient) -> None:
    monitor = FakeMonitor(name="atomic-red-team", items=[
        _mk_item("https://example.com/a"),
        _mk_item("https://example.com/b"),
    ])
    drafter = FakeDrafter(response=json.dumps(_VALID_DRAFT))
    with Session(client.app.state.engine) as s:
        set_setting(s, "daily_call_budget", "10")
        summary = discovery_service.tick(s, drafter=drafter, monitors=[monitor])
        assert summary["items_seen"] == 2
        assert summary["proposed"] == 2  # one draft per item, both queued
        assert summary["deduped"] == 0
        assert drafter.calls == 2
        # Both URLs logged regardless of whether propose succeeded.
        logs = list(s.exec(select(SourceFetchLog)))
        assert {l.item_url for l in logs} == {"https://example.com/a", "https://example.com/b"}


def test_second_run_skips_previously_fetched_urls(client: TestClient) -> None:
    monitor = FakeMonitor(name="atomic-red-team", items=[_mk_item("https://example.com/a")])
    drafter = FakeDrafter(response=json.dumps(_VALID_DRAFT))
    with Session(client.app.state.engine) as s:
        set_setting(s, "daily_call_budget", "10")
        discovery_service.tick(s, drafter=drafter, monitors=[monitor])
        # Second tick with the same URL: dedup hits before LLM is called.
        drafter.calls = 0
        summary = discovery_service.tick(s, drafter=drafter, monitors=[monitor])
        assert summary["deduped"] == 1
        assert summary["proposed"] == 0
        assert drafter.calls == 0


def test_failing_monitor_does_not_abort_other_monitors(client: TestClient) -> None:
    bad = FakeMonitor(name="lakera", raises=RuntimeError("network exploded"))
    good = FakeMonitor(name="atomic-red-team", items=[_mk_item("https://example.com/x")])
    drafter = FakeDrafter(response=json.dumps(_VALID_DRAFT))
    with Session(client.app.state.engine) as s:
        set_setting(s, "daily_call_budget", "10")
        summary = discovery_service.tick(s, drafter=drafter, monitors=[bad, good])
        assert "lakera" in summary["monitor_errors"]
        assert summary["proposed"] == 1


def test_budget_exhausted_stops_loop_cleanly(client: TestClient) -> None:
    monitor = FakeMonitor(name="atomic-red-team", items=[
        _mk_item("https://example.com/a"),
        _mk_item("https://example.com/b"),
        _mk_item("https://example.com/c"),
    ])
    drafter = FakeDrafter(response=json.dumps(_VALID_DRAFT))
    with Session(client.app.state.engine) as s:
        set_setting(s, "daily_call_budget", "1")
        summary = discovery_service.tick(s, drafter=drafter, monitors=[monitor])
        assert summary["budget_exhausted"] is True
        # First item draft succeeded, then budget gone — remaining two are NOT
        # logged so the next run after budget reset will catch them.
        logs = list(s.exec(select(SourceFetchLog)))
        assert len(logs) == 1


def test_invalid_llm_response_logs_but_doesnt_propose(client: TestClient) -> None:
    monitor = FakeMonitor(name="atomic-red-team", items=[_mk_item("https://example.com/a")])
    drafter = FakeDrafter(response="not json")
    with Session(client.app.state.engine) as s:
        set_setting(s, "daily_call_budget", "10")
        summary = discovery_service.tick(s, drafter=drafter, monitors=[monitor])
        assert summary["drafter_errors"] == 1
        assert summary["proposed"] == 0
        # URL still logged so we don't retry the same bad input forever.
        logs = list(s.exec(select(SourceFetchLog)))
        assert len(logs) == 1
        assert logs[0].proposed_signal_id is None


def test_should_run_respects_once_per_day_gate(client: TestClient) -> None:
    with Session(client.app.state.engine) as s:
        # Never run before → should run.
        assert discovery_service.should_run(s, now=datetime.now(UTC), min_interval_hours=23) is True
        set_setting(s, "discovery.last_run_at", datetime.now(UTC).isoformat())
        # Just ran → should not.
        assert discovery_service.should_run(s, now=datetime.now(UTC), min_interval_hours=23) is False
        # 24h later → should again.
        later = datetime.now(UTC) + timedelta(hours=24)
        assert discovery_service.should_run(s, now=later, min_interval_hours=23) is True


def test_tick_stamps_last_run_at(client: TestClient) -> None:
    monitor = FakeMonitor(name="atomic-red-team", items=[])
    drafter = FakeDrafter(response="")
    with Session(client.app.state.engine) as s:
        set_setting(s, "daily_call_budget", "10")
        discovery_service.tick(s, drafter=drafter, monitors=[monitor])
        assert get_setting(s, "discovery.last_run_at") is not None
