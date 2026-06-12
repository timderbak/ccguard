"""IOA correlation detectors (Behavioral Detection, Stage 3 + ТЗ-02).

Two pure kernels over a list of ``SequenceInputEvent`` records:

* :func:`detect_exfil_sequence` — ``cred.read.*`` followed by ``egress.*`` in
  window (Stage 3). Emits ``ioa.exfil_sequence`` (``critical``).
* :func:`detect_staging_chain` — a sensitive/recon read followed by a staging
  write (hidden/temp path), egress OPTIONAL. Emits ``ioa.staging_chain`` with
  severity by suspiciousness (``warn`` staged / ``critical`` full chain /
  ``info`` weak). The early-detect win: it fires on the write, before exfil.

Both are session-scoped (ТЗ-01): events are grouped by ``session_id`` and the
kernel runs per group, with NULL-session events sharing a machine-scope sentinel
group. The orchestrator :func:`tick` runs BOTH detectors for every machine in a
single scheduler pass.
"""
from __future__ import annotations

import json
import logging
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Iterable

log = logging.getLogger(__name__)


@dataclass(frozen=True)
class SequenceInputEvent:
    """One per-event input to the sequence detector.

    ``ts`` must be tz-aware (UTC). ``signals`` is a tuple of catalog IDs.
    ``session_id`` (ТЗ-01) is the Claude Code session the event belongs to;
    ``None`` for events from agents that predate session attribution. The pure
    kernel ignores it — grouping happens in the orchestrator — so it defaults
    to ``None`` and existing kernel callers/tests are unaffected.
    """

    ts: datetime
    signals: tuple[str, ...]
    session_id: str | None = None


@dataclass(frozen=True)
class ExfilMatch:
    """A matched cred→egress pair. Persisted into ``FindingRecord.payload_json``."""

    cred_ts: datetime
    cred_signal: str
    egress_ts: datetime
    egress_signal: str
    elapsed_seconds: float


def detect_exfil_sequence(
    events: Iterable[SequenceInputEvent],
    window_minutes: float,
    cred_prefix: str,
    egress_prefix: str,
) -> ExfilMatch | None:
    """Return the first cred→egress pair within ``window_minutes``, or ``None``.

    "First" means: the earliest cred event that has any egress event with
    ``egress.ts >= cred.ts`` and ``egress.ts - cred.ts <= window``. Within
    that cred event, the earliest egress event in window wins. Events with
    both prefixes on the same row produce a zero-gap match.
    """
    sorted_events = sorted(events, key=lambda e: e.ts)
    if not sorted_events:
        return None

    window = timedelta(minutes=window_minutes)
    for i, cred_evt in enumerate(sorted_events):
        cred_hit = next((s for s in cred_evt.signals if s.startswith(cred_prefix)), None)
        if cred_hit is None:
            continue
        same_row_egress = next(
            (s for s in cred_evt.signals if s.startswith(egress_prefix)), None
        )
        if same_row_egress is not None:
            return ExfilMatch(
                cred_ts=cred_evt.ts,
                cred_signal=cred_hit,
                egress_ts=cred_evt.ts,
                egress_signal=same_row_egress,
                elapsed_seconds=0.0,
            )
        for later in sorted_events[i + 1 :]:
            gap = later.ts - cred_evt.ts
            if gap > window:
                break
            egress_hit = next(
                (s for s in later.signals if s.startswith(egress_prefix)), None
            )
            if egress_hit is not None:
                return ExfilMatch(
                    cred_ts=cred_evt.ts,
                    cred_signal=cred_hit,
                    egress_ts=later.ts,
                    egress_signal=egress_hit,
                    elapsed_seconds=gap.total_seconds(),
                )
    return None


@dataclass(frozen=True)
class StagingMatch:
    """A matched trigger→staging-write[→egress] chain (ТЗ-02).

    ``egress_present`` distinguishes the early-detect case (read→stage, exfil not
    yet observed) from the full kill chain (read→stage→exfil). Persisted into
    ``FindingRecord.payload_json``.
    """

    trigger_ts: datetime
    trigger_signal: str
    write_ts: datetime
    write_signal: str
    egress_present: bool
    egress_ts: datetime | None
    egress_signal: str | None
    elapsed_seconds: float
    # ТЗ-03: True when the trigger event carried an external-content signal —
    # the IPI signature. Default False keeps ТЗ-02 callers/tests unaffected.
    external_trigger: bool = False


def detect_staging_chain(
    events: Iterable[SequenceInputEvent],
    window_minutes: float,
    *,
    trigger_prefixes: tuple[str, ...],
    hidden_signal: str,
    normal_signal: str,
    egress_prefix: str,
    external_signal: str | None = None,
) -> StagingMatch | None:
    """Return the first trigger→staging-write chain within ``window_minutes``.

    The match needs only two links: a trigger (sensitive/recon read) followed by
    a staging write in window. A hidden write is preferred over a normal one when
    both sit in the window (it carries higher severity downstream). egress is
    OPTIONAL — if an egress follows the write in window, ``egress_present`` is set
    (full kill chain), otherwise the match still counts (early detect, the whole
    point of staging detection). The write must be a LATER event than the trigger
    (a single tool call that both reads-sensitive and writes is not a chain).

    ТЗ-03: ``external_signal`` (if given) is BOTH an additional valid trigger and
    the IPI marker — when the matched trigger event carries it, ``external_trigger``
    is set and the orchestrator upgrades severity. It stays OPTIONAL: chains
    triggered by ordinary recon/cred reads still match unchanged.

    Pure function: no DB, mirrors :func:`detect_exfil_sequence`. Grouping by
    session happens in the orchestrator.
    """
    sorted_events = sorted(events, key=lambda e: e.ts)
    if not sorted_events:
        return None

    def _trigger_hit(ev: SequenceInputEvent) -> str | None:
        for s in ev.signals:
            if s.startswith(trigger_prefixes) or (
                external_signal is not None and s == external_signal
            ):
                return s
        return None

    window = timedelta(minutes=window_minutes)
    for i, trig_evt in enumerate(sorted_events):
        trig_hit = _trigger_hit(trig_evt)
        if trig_hit is None:
            continue
        external_trigger = (
            external_signal is not None and external_signal in trig_evt.signals
        )

        # Find the staging write after the trigger, in window. Prefer a hidden
        # write; fall back to a normal one if no hidden appears in the window.
        hidden_hit: tuple[datetime, str] | None = None
        normal_hit: tuple[datetime, str] | None = None
        for later in sorted_events[i + 1 :]:
            if later.ts - trig_evt.ts > window:
                break
            if hidden_signal in later.signals:
                hidden_hit = (later.ts, hidden_signal)
                break
            if normal_signal in later.signals and normal_hit is None:
                normal_hit = (later.ts, normal_signal)
        write = hidden_hit or normal_hit
        if write is None:
            continue
        write_ts, write_signal = write

        # Optional egress AFTER the write, in window. Presence only.
        egress_present = False
        egress_ts: datetime | None = None
        egress_signal: str | None = None
        for ev in sorted_events:
            if ev.ts < write_ts or ev.ts - write_ts > window:
                continue
            hit = next((s for s in ev.signals if s.startswith(egress_prefix)), None)
            if hit is not None:
                egress_present = True
                egress_ts = ev.ts
                egress_signal = hit
                break

        return StagingMatch(
            trigger_ts=trig_evt.ts,
            trigger_signal=trig_hit,
            write_ts=write_ts,
            write_signal=write_signal,
            egress_present=egress_present,
            egress_ts=egress_ts,
            egress_signal=egress_signal,
            elapsed_seconds=(write_ts - trig_evt.ts).total_seconds(),
            external_trigger=external_trigger,
        )
    return None


# --- Orchestrator ---------------------------------------------------------
# Imports kept here (not at top) to keep the pure kernel above dependency-free.

from sqlalchemy import func  # noqa: E402
from sqlmodel import Session, select  # noqa: E402

from ccguard.server.db.models import (  # noqa: E402
    FindingRecord,
    Machine,
    ToolUseEvent,
)
from ccguard.server.services import settings_service  # noqa: E402
from ccguard.server.services._utc import aware_utc  # noqa: E402
from ccguard.server.services.sequence_constants import (  # noqa: E402
    ALLOWLISTED_WRITE_MARKERS,
    CRED_PREFIX,
    DEFAULT_LOOKBACK_HOURS,
    DEFAULT_STAGING_THRESHOLDS,
    DEFAULT_STAGING_WEIGHTS,
    DEFAULT_WINDOW_MINUTES,
    EGRESS_PREFIX,
    EXTERNAL_CONTENT_SIGNAL,
    SEQUENCE_RULE_ID,
    STAGING_HIDDEN_SIGNAL,
    STAGING_NORMAL_SIGNAL,
    STAGING_RULE_ID,
    STAGING_SUPPRESSED_RULE_ID,
    STAGING_TRIGGER_PREFIXES,
)

# Severity ordering for dedup: a benign finding must never shadow a worse one.
_SEVERITY_RANK: dict[str, int] = {"info": 0, "warn": 1, "block": 2, "critical": 3}


def _load_tunables(session: Session) -> tuple[float, float]:
    """Read (window_minutes, lookback_hours) from SettingsRecord, falling back
    to defaults on missing or unparseable values."""

    def _f(key: str, default: float) -> float:
        raw = settings_service.get_setting(session, key)
        if raw is None:
            return default
        try:
            return float(raw)
        except (TypeError, ValueError):
            log.warning("sequence: bad %s=%r, using default %s", key, raw, default)
            return default

    return (
        _f("sequence.window_minutes", DEFAULT_WINDOW_MINUTES),
        _f("sequence.lookback_hours", DEFAULT_LOOKBACK_HOURS),
    )


def _same_day_finding_exists(
    session: Session,
    machine_id: str,
    today_utc: datetime,
    rule_id: str = SEQUENCE_RULE_ID,
) -> bool:
    today_iso = today_utc.date().isoformat()
    stmt = (
        select(FindingRecord)
        .where(FindingRecord.machine_id == machine_id)
        .where(FindingRecord.rule_id == rule_id)
        .where(func.date(FindingRecord.discovered_at) == today_iso)
        .limit(1)
    )
    return session.exec(stmt).first() is not None


def _load_events(
    session: Session, machine_id: str, since: datetime
) -> list[SequenceInputEvent]:
    """Load events with signals for this machine since ``since``.

    Same SQLite-tz-naive normalization as risk_service._load_events.
    """
    stmt = (
        select(ToolUseEvent)
        .where(ToolUseEvent.machine_id == machine_id)
        .where(ToolUseEvent.ts >= since)
        .where(ToolUseEvent.signals_json != "[]")
    )
    out: list[SequenceInputEvent] = []
    for row in session.exec(stmt):
        try:
            sigs = json.loads(row.signals_json)
        except (TypeError, ValueError):
            continue
        if not isinstance(sigs, list) or not sigs:
            continue
        out.append(
            SequenceInputEvent(
                ts=aware_utc(row.ts),
                signals=tuple(str(s) for s in sigs),
                session_id=row.session_id,
            )
        )
    return out


# Sentinel group key for events whose session_id is NULL (legacy agents). A
# unique object so it can never collide with a real session id string. All
# NULL-session events share this one group → machine-scope fallback behavior.
_NO_SESSION = object()


def _group_by_session(
    events: list[SequenceInputEvent],
) -> dict[object, list[SequenceInputEvent]]:
    """Bucket events by session_id; NULL-session events share ``_NO_SESSION``."""
    groups: dict[object, list[SequenceInputEvent]] = {}
    for e in events:
        key: object = e.session_id if e.session_id is not None else _NO_SESSION
        groups.setdefault(key, []).append(e)
    return groups


def evaluate_one(session: Session, machine_id: str) -> FindingRecord | None:
    """Detect an exfil sequence for one machine and emit a finding if matched."""
    # Deterministic cred->egress / staging IOA fire from the FIRST event — they
    # are signal-sequence patterns, not statistical anomalies, so NO warm
    # baseline is required. The warm gate only blinded fresh machines for ~7 days,
    # exactly when a quiet attacker on a new endpoint is most dangerous. (The
    # statistical anomaly engine keeps its own warmup; this is the IOA path.)

    window_min, lookback_h = _load_tunables(session)
    now = datetime.now(UTC)
    since = now - timedelta(hours=lookback_h)
    events = _load_events(session, machine_id, since)
    if not events:
        return None

    # ТЗ-01: correlate within each session independently so a cred-read in one
    # session is never paired with an egress in another (that would be a false
    # positive — unrelated work sharing a machine). NULL-session events from
    # legacy agents share the ``_NO_SESSION`` group, preserving machine-scope
    # behavior. The pure kernel is run per group; the earliest cred match across
    # groups wins (mirrors the kernel's own "earliest cred wins" semantics).
    best: tuple[ExfilMatch, str | None] | None = None
    for key, group_events in _group_by_session(events).items():
        m = detect_exfil_sequence(group_events, window_min, CRED_PREFIX, EGRESS_PREFIX)
        if m is None:
            continue
        sid = None if key is _NO_SESSION else str(key)
        if best is None or m.cred_ts < best[0].cred_ts:
            best = (m, sid)

    if best is None:
        return None
    match, matched_session_id = best

    if _same_day_finding_exists(session, machine_id, now):
        return None

    payload = {
        "cred_ts": match.cred_ts.isoformat(),
        "cred_signal": match.cred_signal,
        "egress_ts": match.egress_ts.isoformat(),
        "egress_signal": match.egress_signal,
        "elapsed_seconds": match.elapsed_seconds,
        "window_minutes": window_min,
        "lookback_hours": lookback_h,
        # The session the match occurred in (None for legacy NULL-session
        # events). Dedup stays machine-level this pass; payload surfaces the
        # session so the UI can show which one matched.
        "session_id": matched_session_id,
    }
    finding = FindingRecord(
        machine_id=machine_id,
        inventory_id=None,
        rule_id=SEQUENCE_RULE_ID,
        # ТЗ-02 severity fix: "high" is NOT in the schema Severity literal
        # (info/warn/block/critical). A confirmed cred→egress is the strongest
        # exfil signal we emit → critical.
        severity="critical",
        discovered_at=now,
        payload_json=json.dumps(payload, allow_nan=False),
    )
    session.add(finding)
    session.commit()
    session.refresh(finding)
    return finding


def _load_staging_cfg(session: Session) -> tuple[dict[str, float], dict[str, float]]:
    """Read scoring weights + thresholds from SettingsRecord (ТЗ-04 §3).

    Keys ``staging.weight.<factor>`` / ``staging.threshold.<tier>``; missing or
    unparseable values fall back to the conservative defaults. Tuning the noise
    floor needs no redeploy.
    """

    def _f(key: str, default: float) -> float:
        raw = settings_service.get_setting(session, key)
        if raw is None:
            return default
        try:
            return float(raw)
        except (TypeError, ValueError):
            log.warning("staging: bad %s=%r, using default %s", key, raw, default)
            return default

    weights = {
        k: _f(f"staging.weight.{k}", v) for k, v in DEFAULT_STAGING_WEIGHTS.items()
    }
    thresholds = {
        k: _f(f"staging.threshold.{k}", v)
        for k, v in DEFAULT_STAGING_THRESHOLDS.items()
    }
    return weights, thresholds


def _score_staging(
    match: StagingMatch, weights: dict[str, float]
) -> tuple[float, dict[str, float]]:
    """Additive, explainable risk score for a staging match (ТЗ-04 §2).

    Each risk factor contributes its weight; the breakdown is returned for the
    finding payload so triage sees *why* and thresholds can be tuned.
    """
    factors: dict[str, float] = {}
    if match.write_signal == STAGING_HIDDEN_SIGNAL:
        factors["hidden"] = weights["hidden"]
    if match.external_trigger:
        factors["external"] = weights["external"]
    if match.egress_present:
        factors["egress"] = weights["egress"]
    return sum(factors.values()), factors


def _score_to_severity(score: float, thresholds: dict[str, float]) -> str:
    """Map a score to a schema-valid severity. Calibrated so ТЗ-02/03 attack
    outcomes (warn/block/critical) are preserved; weak combos fall to info."""
    if score >= thresholds["critical"]:
        return "critical"
    if score >= thresholds["block"]:
        return "block"
    if score >= thresholds["warn"]:
        return "warn"
    return "info"


def _write_event_markers(
    group_events: list[SequenceInputEvent], write_ts: datetime, write_signal: str
) -> set[str]:
    """Allowlist markers (fs.write.cache/vcs) carried by the matched write event.

    The kernel keeps StagingMatch path-free (privacy); we re-inspect the write
    event in the group to read its benign-category markers. Empty set → the
    write is not a known build/package cache → NOT allowlisted.
    """
    for ev in group_events:
        if ev.ts == write_ts and write_signal in ev.signals:
            return set(ev.signals) & ALLOWLISTED_WRITE_MARKERS
    return set()


def _max_staging_rank_today(
    session: Session, machine_id: str, rule_id: str, today_utc: datetime
) -> int:
    """Highest severity rank already recorded today under ``rule_id``.

    Severity-aware dedup (ТЗ-04): a benign/earlier finding must never shadow a
    worse one later the same day. Returns -1 when none exist.
    """
    today_iso = today_utc.date().isoformat()
    rows = session.exec(
        select(FindingRecord)
        .where(FindingRecord.machine_id == machine_id)
        .where(FindingRecord.rule_id == rule_id)
        .where(func.date(FindingRecord.discovered_at) == today_iso)
    ).all()
    return max((_SEVERITY_RANK.get(r.severity, 0) for r in rows), default=-1)


def evaluate_one_staging(session: Session, machine_id: str) -> FindingRecord | None:
    """Detect a staging chain for one machine, applying allowlist + scoring.

    Layered over the ТЗ-02/03 kernel (untouched): per session group we take the
    kernel match, suppress known build/package noise (allowlist), score the rest
    additively, and surface the MOST SEVERE non-suppressed candidate (so build
    noise in one session never hides a real chain in another). Dedup is
    severity-aware per rule_id so a benign finding can't shadow an attack.
    """
    # Deterministic cred->egress / staging IOA fire from the FIRST event — they
    # are signal-sequence patterns, not statistical anomalies, so NO warm
    # baseline is required. The warm gate only blinded fresh machines for ~7 days,
    # exactly when a quiet attacker on a new endpoint is most dangerous. (The
    # statistical anomaly engine keeps its own warmup; this is the IOA path.)

    window_min, lookback_h = _load_tunables(session)
    weights, thresholds = _load_staging_cfg(session)
    now = datetime.now(UTC)
    since = now - timedelta(hours=lookback_h)
    events = _load_events(session, machine_id, since)
    if not events:
        return None

    # Build a verdict per session group, then select the most severe.
    candidates: list[dict] = []
    for key, group_events in _group_by_session(events).items():
        m = detect_staging_chain(
            group_events,
            window_min,
            trigger_prefixes=STAGING_TRIGGER_PREFIXES,
            hidden_signal=STAGING_HIDDEN_SIGNAL,
            normal_signal=STAGING_NORMAL_SIGNAL,
            egress_prefix=EGRESS_PREFIX,
            external_signal=EXTERNAL_CONTENT_SIGNAL,
        )
        if m is None:
            continue
        sid = None if key is _NO_SESSION else str(key)
        markers = _write_event_markers(group_events, m.write_ts, m.write_signal)
        score, factors = _score_staging(m, weights)
        suppressed = bool(markers)
        severity = "info" if suppressed else _score_to_severity(score, thresholds)
        # Selection rank: suppressed candidates rank below every real one so a
        # real chain elsewhere always wins; among reals, higher severity wins.
        select_rank = -1 if suppressed else _SEVERITY_RANK[severity]
        candidates.append(
            {
                "match": m,
                "session_id": sid,
                "suppressed": suppressed,
                "suppression_reason": sorted(markers)[0] if markers else None,
                "score": score,
                "factors": factors,
                "severity": severity,
                "select_rank": select_rank,
            }
        )

    if not candidates:
        return None
    best = max(candidates, key=lambda c: (c["select_rank"], c["score"], -c["match"].trigger_ts.timestamp()))

    match: StagingMatch = best["match"]
    rule_id = STAGING_SUPPRESSED_RULE_ID if best["suppressed"] else STAGING_RULE_ID
    new_rank = _SEVERITY_RANK[best["severity"]]

    # Severity-aware dedup: emit only if strictly more severe than what today
    # already holds under this rule_id — escalations surface, repeats are quiet,
    # and a benign finding never shadows a later attack.
    if new_rank <= _max_staging_rank_today(session, machine_id, rule_id, now):
        return None

    payload = {
        "trigger_ts": match.trigger_ts.isoformat(),
        "trigger_signal": match.trigger_signal,
        "write_ts": match.write_ts.isoformat(),
        "write_signal": match.write_signal,
        "egress_present": match.egress_present,
        "egress_ts": match.egress_ts.isoformat() if match.egress_ts else None,
        "egress_signal": match.egress_signal,
        "elapsed_seconds": match.elapsed_seconds,
        "window_minutes": window_min,
        "lookback_hours": lookback_h,
        "session_id": best["session_id"],
        "external_trigger": match.external_trigger,
        "external_signal": EXTERNAL_CONTENT_SIGNAL if match.external_trigger else None,
        # ТЗ-04 transparency: scoring breakdown + suppression status.
        "score": best["score"],
        "score_factors": best["factors"],
        "thresholds": thresholds,
        "suppressed": best["suppressed"],
        "suppression_reason": best["suppression_reason"],
    }
    finding = FindingRecord(
        machine_id=machine_id,
        inventory_id=None,
        rule_id=rule_id,
        severity=best["severity"],
        discovered_at=now,
        payload_json=json.dumps(payload, allow_nan=False),
    )
    session.add(finding)
    session.commit()
    session.refresh(finding)
    return finding


def tick(session: Session) -> dict[str, object]:
    """Detect exfil sequences AND staging chains for every machine in one pass.

    Both detectors run from this single scheduler tick (ТЗ-02 §4) — no separate
    scheduler. They are independent: a machine can emit one, both, or neither.
    """
    machines = list(session.exec(select(Machine)))
    emitted = 0
    errors: list[str] = []
    for m in machines:
        for detector in (evaluate_one, evaluate_one_staging):
            try:
                if detector(session, m.machine_id) is not None:
                    emitted += 1
            except Exception as exc:  # noqa: BLE001 — boundary swallow is intentional
                try:
                    session.rollback()
                except Exception:  # noqa: BLE001
                    pass
                errors.append(f"{m.machine_id}/{detector.__name__}: {exc}")
                log.warning("sequence tick error: %s", errors[-1])
    return {
        "machines_evaluated": len(machines),
        "findings_emitted": emitted,
        "errors": errors,
    }
