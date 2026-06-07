"""Universal stage-chain correlation engine (ТЗ-09).

Runs ALONGSIDE ``sequence_service`` (which is NOT modified). Where the ТЗ-01..07
correlators are five hand-written kernels, this is ONE generic executor that
reads any :class:`ChainScenario` from the DB (data, not code) and fires when its
sequence of STAGES completes within ``window_seconds`` inside a single
correlation session.

The headline property (ТЗ-09 "gold"): a step references a STAGE
(``tactic``), not a channel. The engine matches "any event whose derived stage
== the step's tactic", so an ``exfiltration`` step fires on T1567 OR T1048 OR
AML.T0024 — and on a brand-new channel the moment a signal for it exists, with
NO change to the scenario. New scenario = new rows; new channel = new indicator.

Reuses the existing event substrate verbatim: ``ToolUseEvent`` (+ its
``signals_json`` and ``session_id``), per-session grouping, ``FindingRecord``
creation, and same-day dedup — so it slots into the same scheduler tick. The
event → stage bridge is :func:`chain_constants.stages_for_signals`.
"""
from __future__ import annotations

import json
import logging
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta

from sqlalchemy import func
from sqlmodel import Session, select

from ccguard.server.db.models import (
    ChainMatch,
    ChainScenario,
    ChainStep,
    FindingRecord,
    Machine,
    Technique,
    ToolUseEvent,
)
from ccguard.server.services.chain_constants import (
    CHAIN_RULE_PREFIX,
    DEFAULT_LOOKBACK_HOURS,
    stage_for_signal,
    stages_for_signals,
)

log = logging.getLogger(__name__)

_NO_SESSION = object()  # sentinel so NULL-session events never collide

# Scenario severity → FindingRecord vocabulary (info|warn|block|critical).
_SEVERITY_MAP = {
    "low": "warn",
    "medium": "block",
    "high": "critical",
    "info": "info",
    "warn": "warn",
    "block": "block",
    "critical": "critical",
}


def _norm_severity(sev: str) -> str:
    return _SEVERITY_MAP.get((sev or "").lower(), "block")


def _aware(ts: datetime) -> datetime:
    """Normalize a (possibly SQLite-naive) timestamp to tz-aware UTC."""
    return ts if ts.tzinfo is not None else ts.replace(tzinfo=UTC)


# --------------------------------------------------------------------------- #
# Pure data + kernel (no DB) — independently testable                         #
# --------------------------------------------------------------------------- #
@dataclass(frozen=True)
class _Event:
    ts: datetime
    signals: tuple[str, ...]
    session_id: str | None


@dataclass(frozen=True)
class _Step:
    step_index: int
    tactic: str
    optional: bool


@dataclass(frozen=True)
class MatchedStep:
    step_index: int
    tactic: str
    signal: str
    ts: datetime


def _ev_stages(ev: _Event) -> set[str]:
    return stages_for_signals(ev.signals)


def _pick_signal(ev: _Event, tactic: str) -> str:
    for s in ev.signals:
        if stage_for_signal(s) == tactic:
            return s
    return ""


def _required_satisfied(steps: list[_Step], matched: list[MatchedStep]) -> bool:
    required = {s.step_index for s in steps if not s.optional}
    return required <= {m.step_index for m in matched}


def _greedy_ordered(
    steps: list[_Step], events: list[_Event], start_idx: int, window_seconds: int
) -> list[MatchedStep] | None:
    """Greedy ordered match starting at events[start_idx]. Steps must complete
    within window_seconds of the first matched step; optional steps may be
    skipped when absent."""
    window_start = events[start_idx].ts
    progress = 0
    matched: list[MatchedStep] = []
    for ev in events[start_idx:]:
        if (ev.ts - window_start).total_seconds() > window_seconds:
            break
        stages = _ev_stages(ev)
        # Advance through steps this single event can satisfy (one real match per
        # event; an optional step with no match is skipped so the SAME event can
        # satisfy the following required step).
        while progress < len(steps):
            step = steps[progress]
            if step.tactic in stages:
                matched.append(
                    MatchedStep(step.step_index, step.tactic, _pick_signal(ev, step.tactic), ev.ts)
                )
                progress += 1
                break
            if step.optional:
                progress += 1
                continue
            break  # required step unmet by this event → wait for the next event
        if _required_satisfied(steps, matched):
            return matched
    return matched if _required_satisfied(steps, matched) else None


def match_scenario(
    steps: list[_Step], events: list[_Event], window_seconds: int, require_order: bool
) -> list[MatchedStep] | None:
    """Return the matched steps if the scenario fires over these (single-session,
    time-sorted) events, else None. Pure — no DB, no side effects."""
    if not steps:
        return None
    events = sorted(events, key=lambda e: e.ts)
    if require_order:
        first = steps[0]
        for i, ev in enumerate(events):
            if first.tactic in _ev_stages(ev) or first.optional:
                res = _greedy_ordered(steps, events, i, window_seconds)
                if res is not None:
                    return res
        return None
    # Unordered: every required stage must occur within a single window anchored
    # at some event.
    for i, anchor in enumerate(events):
        win = [e for e in events[i:] if (e.ts - anchor.ts).total_seconds() <= window_seconds]
        matched: list[MatchedStep] = []
        ok = True
        for step in steps:
            ev = next((e for e in win if step.tactic in _ev_stages(e)), None)
            if ev is None:
                if step.optional:
                    continue
                ok = False
                break
            matched.append(MatchedStep(step.step_index, step.tactic, _pick_signal(ev, step.tactic), ev.ts))
        if ok and _required_satisfied(steps, matched):
            return matched
    return None


# --------------------------------------------------------------------------- #
# DB glue: load events, dedup, emit findings                                  #
# --------------------------------------------------------------------------- #
def _load_events(session: Session, machine_id: str, since: datetime) -> list[_Event]:
    rows = session.exec(
        select(ToolUseEvent)
        .where(ToolUseEvent.machine_id == machine_id)
        .where(ToolUseEvent.ts >= since)
        .where(ToolUseEvent.signals_json != "[]")
    ).all()
    out: list[_Event] = []
    for row in rows:
        try:
            sigs = json.loads(row.signals_json)
        except (TypeError, ValueError):
            continue
        if not isinstance(sigs, list) or not sigs:
            continue
        out.append(
            _Event(ts=_aware(row.ts), signals=tuple(str(s) for s in sigs), session_id=row.session_id)
        )
    return out


def _group_by_session(events: list[_Event]) -> dict[object, list[_Event]]:
    groups: dict[object, list[_Event]] = {}
    for e in events:
        key: object = e.session_id if e.session_id is not None else _NO_SESSION
        groups.setdefault(key, []).append(e)
    return groups


def _same_day_finding_exists(
    session: Session, machine_id: str, rule_id: str, now: datetime
) -> bool:
    today_iso = now.date().isoformat()
    stmt = (
        select(FindingRecord)
        .where(FindingRecord.machine_id == machine_id)
        .where(FindingRecord.rule_id == rule_id)
        .where(func.date(FindingRecord.discovered_at) == today_iso)
        .limit(1)
    )
    return session.exec(stmt).first() is not None


def _stage_techniques(session: Session, tactics: set[str]) -> dict[str, list[str]]:
    """For each matched stage, the in-scope techniques covering it (taxonomy
    enrichment) — "T1567 (attack)", "AML.T0024 (atlas)", etc."""
    if not tactics:
        return {}
    rows = session.exec(
        select(Technique).where(Technique.tactic.in_(tactics)).where(Technique.in_scope == True)  # noqa: E712
    ).all()
    out: dict[str, list[str]] = {}
    for t in rows:
        out.setdefault(t.tactic, []).append(f"{t.technique_id} ({t.framework})")
    for v in out.values():
        v.sort()
    return out


def _emit(
    session: Session,
    machine_id: str,
    scenario: ChainScenario,
    steps: list[_Step],
    session_id: str | None,
    matched: list[MatchedStep],
    now: datetime,
) -> FindingRecord:
    rule_id = CHAIN_RULE_PREFIX + scenario.scenario_key
    matched_payload = [
        {"step_index": m.step_index, "tactic": m.tactic, "signal": m.signal, "ts": m.ts.isoformat()}
        for m in matched
    ]
    matched_tactics = {m.tactic for m in matched}
    payload = {
        "scenario_key": scenario.scenario_key,
        "scenario_name": scenario.name,
        "session_id": session_id,
        "window_seconds": scenario.window_seconds,
        "require_order": scenario.require_order,
        "control_type": "DETECT",  # correlations DETECT (ТЗ-08 vocabulary)
        "matched_steps": matched_payload,
        "stage_techniques": _stage_techniques(session, matched_tactics),
        "elapsed_seconds": (
            max(m.ts for m in matched) - min(m.ts for m in matched)
        ).total_seconds(),
    }
    finding = FindingRecord(
        machine_id=machine_id,
        inventory_id=None,
        rule_id=rule_id,
        severity=_norm_severity(scenario.severity),
        discovered_at=now,
        payload_json=json.dumps(payload, allow_nan=False),
    )
    session.add(finding)
    session.commit()
    session.refresh(finding)
    session.add(
        ChainMatch(
            scenario_key=scenario.scenario_key,
            machine_id=machine_id,
            session_id=session_id,
            matched_at=now,
            finding_id=finding.id,
            matched_steps_json=json.dumps(matched_payload, allow_nan=False),
        )
    )
    session.commit()
    return finding


def _steps_for(session: Session, scenario_key: str) -> list[_Step]:
    rows = session.exec(
        select(ChainStep)
        .where(ChainStep.scenario_key == scenario_key)
        .order_by(ChainStep.step_index)
    ).all()
    return [_Step(r.step_index, r.tactic, r.optional) for r in rows]


def evaluate_scenario(
    session: Session,
    machine_id: str,
    scenario: ChainScenario,
    steps: list[_Step] | None = None,
    now: datetime | None = None,
) -> FindingRecord | None:
    """Evaluate one scenario for one machine. Emits at most one finding (same-day
    dedup per scenario rule_id). Returns the finding or None."""
    now = now or datetime.now(UTC)
    if steps is None:
        steps = _steps_for(session, scenario.scenario_key)
    if not steps:
        return None
    rule_id = CHAIN_RULE_PREFIX + scenario.scenario_key
    if _same_day_finding_exists(session, machine_id, rule_id, now):
        return None  # already emitted today for this machine

    since = now - timedelta(hours=DEFAULT_LOOKBACK_HOURS)
    events = _load_events(session, machine_id, since)
    if not events:
        return None

    best: tuple[str | None, list[MatchedStep], datetime] | None = None
    for key, evs in _group_by_session(events).items():
        matched = match_scenario(steps, evs, scenario.window_seconds, scenario.require_order)
        if not matched:
            continue
        sid = None if key is _NO_SESSION else str(key)
        completion = max(m.ts for m in matched)
        if best is None or completion < best[2]:
            best = (sid, matched, completion)
    if best is None:
        return None
    return _emit(session, machine_id, scenario, steps, best[0], best[1], now)


def evaluate_machine(session: Session, machine_id: str, now: datetime | None = None) -> list[FindingRecord]:
    """Run every enabled scenario for one machine. Returns emitted findings."""
    now = now or datetime.now(UTC)
    scenarios = session.exec(select(ChainScenario).where(ChainScenario.enabled == True)).all()  # noqa: E712
    out: list[FindingRecord] = []
    for sc in scenarios:
        f = evaluate_scenario(session, machine_id, sc, now=now)
        if f is not None:
            out.append(f)
    return out


def tick(session: Session) -> dict[str, object]:
    """Scheduler entry: evaluate all enabled scenarios for every machine.

    Mirrors ``sequence_service.tick`` shape so it slots into the same scheduled
    job. Independent of the existing correlators — runs beside them.
    """
    scenarios = list(session.exec(select(ChainScenario).where(ChainScenario.enabled == True)))  # noqa: E712
    steps_by = {sc.scenario_key: _steps_for(session, sc.scenario_key) for sc in scenarios}
    machines = list(session.exec(select(Machine)))
    now = datetime.now(UTC)
    emitted = 0
    errors: list[str] = []
    for m in machines:
        for sc in scenarios:
            try:
                if evaluate_scenario(session, m.machine_id, sc, steps_by[sc.scenario_key], now) is not None:
                    emitted += 1
            except Exception as exc:  # noqa: BLE001 — one bad scenario must not kill the tick
                session.rollback()
                errors.append(f"{m.machine_id}/{sc.scenario_key}: {exc}")
                log.warning("chain tick error: %s", errors[-1])
    return {
        "machines_evaluated": len(machines),
        "scenarios_active": len(scenarios),
        "findings_emitted": emitted,
        "errors": errors,
    }
