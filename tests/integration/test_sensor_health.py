"""ТЗ-07: heartbeat ingest + server-side silence/integrity detection."""
from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta

from fastapi.testclient import TestClient
from sqlmodel import Session, select

from ccguard.server.db.models import FindingRecord, Machine
from ccguard.server.services import sensor_health_service, settings_service


def _hb(client: TestClient, headers, machine_id="m1", **extra) -> None:
    body = {"machine_id": machine_id, "agent_version": "0.2", **extra}
    r = client.post("/api/v1/heartbeat", content=json.dumps(body), headers=headers)
    assert r.status_code == 200, r.text


def _set_heartbeat_age(engine, machine_id: str, *, minutes_ago: float,
                       hooks_intact=None, silent_since=None) -> None:
    with Session(engine) as s:
        m = s.get(Machine, machine_id)
        m.last_heartbeat_at = datetime.now(UTC) - timedelta(minutes=minutes_ago)
        m.hooks_intact = hooks_intact
        m.silent_since = silent_since
        s.add(m)
        s.commit()


def _findings(engine, rule_id: str) -> list[FindingRecord]:
    with Session(engine) as s:
        return list(
            s.exec(select(FindingRecord).where(FindingRecord.rule_id == rule_id)).all()
        )


# --- AC1: heartbeat updates last_heartbeat_at --------------------------------


def test_heartbeat_updates_last_heartbeat_at(client, auth_headers) -> None:
    _hb(client, auth_headers, expected_interval_sec=900)
    with Session(client.app.state.engine) as s:  # type: ignore[attr-defined]
        m = s.get(Machine, "m1")
    assert m is not None
    assert m.last_heartbeat_at is not None
    assert m.expected_interval_sec == 900


# --- AC2: quiet-alive machine stays active, no finding -----------------------


def test_quiet_alive_machine_no_finding(client, auth_headers) -> None:
    """Heartbeat fresh, zero tool events → active, NO sensor.silent. The whole
    point: alive-but-idle must not look dead."""
    engine = client.app.state.engine  # type: ignore[attr-defined]
    _hb(client, auth_headers)  # fresh heartbeat, nothing else
    with Session(engine) as s:
        sensor_health_service.tick(s)
    assert _findings(engine, "sensor.silent") == []


# --- AC3: silent detected ----------------------------------------------------


def test_silent_machine_emits_finding(client, auth_headers) -> None:
    engine = client.app.state.engine  # type: ignore[attr-defined]
    _hb(client, auth_headers, expected_interval_sec=900)
    _set_heartbeat_age(engine, "m1", minutes_ago=120)  # well past 15min*3 grace
    with Session(engine) as s:
        sensor_health_service.tick(s)
    findings = _findings(engine, "sensor.silent")
    assert len(findings) == 1
    payload = json.loads(findings[0].payload_json)
    assert payload["silent_minutes"] >= 100


# --- AC4: 🔒 grace window — short pause does NOT panic ------------------------


def test_within_grace_is_stale_not_silent(client, auth_headers) -> None:
    """Reboot/short pause within grace → stale, NO finding."""
    engine = client.app.state.engine  # type: ignore[attr-defined]
    _hb(client, auth_headers, expected_interval_sec=900)  # 15min interval
    _set_heartbeat_age(engine, "m1", minutes_ago=20)  # >15min but < 45min grace
    with Session(engine) as s:
        sensor_health_service.tick(s)
        state = sensor_health_service.lifecycle_state(s, s.get(Machine, "m1"))
    assert state == "stale"
    assert _findings(engine, "sensor.silent") == []


# --- AC5: hooks_intact=false → strong finding --------------------------------


def test_hooks_removed_emits_high_severity(client, auth_headers) -> None:
    engine = client.app.state.engine  # type: ignore[attr-defined]
    _hb(client, auth_headers, hooks_intact=True)   # baseline intact
    _hb(client, auth_headers, hooks_intact=False)  # transition: hook removed
    findings = _findings(engine, "sensor.hooks_removed")
    assert len(findings) == 1
    assert findings[0].severity in ("block", "critical")


def test_hooks_removed_deduped_on_repeat(client, auth_headers) -> None:
    engine = client.app.state.engine  # type: ignore[attr-defined]
    _hb(client, auth_headers, hooks_intact=False)
    _hb(client, auth_headers, hooks_intact=False)  # still false — no second finding
    assert len(_findings(engine, "sensor.hooks_removed")) == 1


# --- AC6: episode dedup ------------------------------------------------------


def test_silent_deduped_across_ticks(client, auth_headers) -> None:
    engine = client.app.state.engine  # type: ignore[attr-defined]
    _hb(client, auth_headers, expected_interval_sec=900)
    _set_heartbeat_age(engine, "m1", minutes_ago=120)
    with Session(engine) as s:
        sensor_health_service.tick(s)
        sensor_health_service.tick(s)
        sensor_health_service.tick(s)
    assert len(_findings(engine, "sensor.silent")) == 1  # one per episode


# --- AC7: recovery closes the episode ----------------------------------------


def test_recovery_clears_episode(client, auth_headers) -> None:
    engine = client.app.state.engine  # type: ignore[attr-defined]
    _hb(client, auth_headers, expected_interval_sec=900)
    _set_heartbeat_age(engine, "m1", minutes_ago=120)
    with Session(engine) as s:
        sensor_health_service.tick(s)
    # machine comes back
    _hb(client, auth_headers, expected_interval_sec=900)
    with Session(engine) as s:
        m = s.get(Machine, "m1")
        assert m.silent_since is None  # episode closed on return
    assert len(_findings(engine, "sensor.recovered")) == 1


# --- AC8: thresholds tunable from settings -----------------------------------


def test_grace_threshold_from_settings(client, auth_headers) -> None:
    engine = client.app.state.engine  # type: ignore[attr-defined]
    _hb(client, auth_headers, expected_interval_sec=900)
    _set_heartbeat_age(engine, "m1", minutes_ago=120)
    with Session(engine) as s:
        # Huge grace multiplier → 120min is now within grace → no finding.
        settings_service.set_setting(s, "sensor.grace_multiplier", "100")
        sensor_health_service.tick(s)
    assert _findings(engine, "sensor.silent") == []


# --- backward compat: legacy machine never sent heartbeat → no alert ---------


def test_legacy_machine_without_heartbeat_not_alerted(client, auth_headers) -> None:
    engine = client.app.state.engine  # type: ignore[attr-defined]
    with Session(engine) as s:
        s.add(Machine(machine_id="legacy", last_heartbeat_at=None))
        s.commit()
        sensor_health_service.tick(s)
    assert _findings(engine, "sensor.silent") == []
