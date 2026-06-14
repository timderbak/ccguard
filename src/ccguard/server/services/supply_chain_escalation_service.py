"""AI-trigger → escalation correlator — the product moat.

The four window correlators (sequence/chain/slow_chain) link ToolUseEvent
SIGNALS within a session. But the AI-ORIGIN trigger — a poisoned/changed MCP
server, a drifted skill/hook/agent, a detected prompt injection — is emitted on
a DIFFERENT path (inventory sync / PostToolUse), as a FindingRecord they never
see. So "MCP rug-pulled → then the agent stole secrets → exfiltrated" was two
disconnected alerts, not one story.

This service bridges that gap at MACHINE scope (the supply-chain compromise is a
machine-level state that primes every later session): an AI-origin TRIGGER
finding, FOLLOWED on the same machine within a window by an endpoint ESCALATION
(exfiltration / C2 / impact event, OR an already-correlated ``ioa.*`` chain),
emits ``ioa.ai_trigger_escalation`` (critical) — naming both ends as one
connected attack. This is exactly the link a classic EDR cannot make: it never
saw the AI-origin cause.

Mirrors the slow_chain tick contract (per-machine try/except, same-UTC-day dedup,
single-session sweep). Tunable via SettingsRecord without a redeploy.
"""
from __future__ import annotations

import json
import logging
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta

from sqlalchemy import func
from sqlmodel import Session, select

from ccguard.server.db.models import FindingRecord, Machine, ToolUseEvent
from ccguard.server.services import settings_service
from ccguard.server.services._utc import aware_utc
from ccguard.server.services.chain_constants import stage_for_signal

log = logging.getLogger(__name__)

RULE_ID = "ioa.ai_trigger_escalation"
SEVERITY = "critical"

# AI-ORIGIN trigger finding rule_ids (prefix match): a compromise of the agent's
# trust surface — supply-chain rug-pull / drift / new untrusted plugin behaviour,
# config tamper, or a detected prompt injection.
TRIGGER_RULE_PREFIXES: tuple[str, ...] = (
    "mcp.rug_pull",
    "hook.rug_pull",
    "skill.rug_pull",
    "agent.rug_pull",
    "skill.drift",
    "agent.drift",
    "hook.content",  # hook content drift
    "persist.agent_config",  # settings.json / .mcp.json tamper (drift_service)
    "prompt_injection",  # cheap PI catalog hit on read content
    "llm.scan",  # server-side semantic PI verdict
)

# Endpoint ESCALATION: only the "right side" stages that are rarely benign, so a
# critical alert is trustworthy. credential-access alone is excluded (reading a
# secret is too common in routine dev to call a supply-chain attack on its own).
ESCALATION_STAGES: frozenset[str] = frozenset(
    {"exfiltration", "command-and-control", "impact"}
)

DEFAULT_WINDOW_HOURS: float = 72.0
SETTING_WINDOW_HOURS = "ai_trigger_escalation.window_hours"


@dataclass(frozen=True)
class Trigger:
    rule_id: str
    ts: datetime


@dataclass(frozen=True)
class Escalation:
    stage: str
    signal: str
    ts: datetime


@dataclass(frozen=True)
class LinkResult:
    trigger: Trigger
    escalation: Escalation


# --- Pure kernel -----------------------------------------------------------


def evaluate_link(
    triggers: list[Trigger], escalations: list[Escalation], *, window_hours: float
) -> LinkResult | None:
    """Link the EARLIEST escalation that is preceded (cause-before-effect) by a
    trigger within ``window_hours`` on the same machine. Returns the linked pair
    (most-recent preceding trigger), or None."""
    if not triggers or not escalations:
        return None
    window = timedelta(hours=window_hours)
    trig_sorted = sorted(triggers, key=lambda t: t.ts)
    for esc in sorted(escalations, key=lambda e: e.ts):
        preceding = [t for t in trig_sorted if t.ts <= esc.ts and (esc.ts - t.ts) <= window]
        if preceding:
            return LinkResult(trigger=preceding[-1], escalation=esc)
    return None


# --- Orchestrator ----------------------------------------------------------


def _window_hours(session: Session) -> float:
    raw = settings_service.get_setting(session, SETTING_WINDOW_HOURS)
    if raw is None:
        return DEFAULT_WINDOW_HOURS
    try:
        return float(raw)
    except (TypeError, ValueError):
        log.warning("ai_trigger_escalation: bad window=%r, using default", raw)
        return DEFAULT_WINDOW_HOURS


def _is_trigger(rule_id: str) -> bool:
    return any(rule_id.startswith(p) for p in TRIGGER_RULE_PREFIXES)


def _load_triggers(session: Session, machine_id: str, since: datetime) -> list[Trigger]:
    stmt = (
        select(FindingRecord)
        .where(FindingRecord.machine_id == machine_id)
        .where(FindingRecord.discovered_at >= since)
    )
    out: list[Trigger] = []
    for row in session.exec(stmt):
        if _is_trigger(row.rule_id):
            out.append(Trigger(rule_id=row.rule_id, ts=aware_utc(row.discovered_at)))
    return out


def _load_escalations(session: Session, machine_id: str, since: datetime) -> list[Escalation]:
    out: list[Escalation] = []
    # (a) endpoint events whose signal resolves to an escalation stage
    ev_stmt = (
        select(ToolUseEvent)
        .where(ToolUseEvent.machine_id == machine_id)
        .where(ToolUseEvent.ts >= since)
        .where(ToolUseEvent.signals_json != "[]")
    )
    for row in session.exec(ev_stmt):
        try:
            sigs = json.loads(row.signals_json)
        except (TypeError, ValueError):
            continue
        if not isinstance(sigs, list):
            continue
        for sid in sigs:
            stage = stage_for_signal(str(sid))
            if stage in ESCALATION_STAGES:
                out.append(Escalation(stage=stage, signal=str(sid), ts=aware_utc(row.ts)))
                break
    # (b) an already-correlated attack chain (ioa.*, not our own) — strongest
    f_stmt = (
        select(FindingRecord)
        .where(FindingRecord.machine_id == machine_id)
        .where(FindingRecord.discovered_at >= since)
    )
    for row in session.exec(f_stmt):
        if row.rule_id.startswith("ioa.") and row.rule_id != RULE_ID:
            out.append(
                Escalation(stage="correlated_chain", signal=row.rule_id,
                           ts=aware_utc(row.discovered_at))
            )
    return out


def _same_day_finding_exists(session: Session, machine_id: str, today_utc: datetime) -> bool:
    today_iso = today_utc.date().isoformat()
    stmt = (
        select(FindingRecord)
        .where(FindingRecord.machine_id == machine_id)
        .where(FindingRecord.rule_id == RULE_ID)
        .where(func.date(FindingRecord.discovered_at) == today_iso)
        .limit(1)
    )
    return session.exec(stmt).first() is not None


def evaluate_one(session: Session, machine_id: str) -> FindingRecord | None:
    """Emit ``ioa.ai_trigger_escalation`` if an AI-origin trigger on this machine
    is followed by an endpoint escalation within the window. Returns it, or None."""
    window_hours = _window_hours(session)
    now = datetime.now(UTC)
    since = now - timedelta(hours=window_hours)

    triggers = _load_triggers(session, machine_id, since)
    escalations = _load_escalations(session, machine_id, since)
    link = evaluate_link(triggers, escalations, window_hours=window_hours)
    if link is None:
        return None
    if _same_day_finding_exists(session, machine_id, now):
        return None

    gap_h = round((link.escalation.ts - link.trigger.ts).total_seconds() / 3600.0, 2)
    payload = {
        "trigger_rule": link.trigger.rule_id,
        "trigger_at": link.trigger.ts.isoformat(),
        "escalation_stage": link.escalation.stage,
        "escalation_signal": link.escalation.signal,
        "escalation_at": link.escalation.ts.isoformat(),
        "gap_hours": gap_h,
        "window_hours": window_hours,
        "narrative": (
            f"AI-origin trigger '{link.trigger.rule_id}' then endpoint "
            f"'{link.escalation.signal}' ({link.escalation.stage}) {gap_h}h later "
            f"on this machine — one connected attack a classic EDR cannot link."
        ),
    }
    finding = FindingRecord(
        machine_id=machine_id,
        inventory_id=None,
        rule_id=RULE_ID,
        severity=SEVERITY,
        discovered_at=now,
        payload_json=json.dumps(payload, allow_nan=False),
    )
    session.add(finding)
    session.commit()
    session.refresh(finding)
    return finding


def tick(session: Session) -> dict[str, object]:
    """Run the AI-trigger→escalation sweep over every machine. Mirrors slow_chain."""
    machines = list(session.exec(select(Machine)))
    emitted = 0
    errors: list[str] = []
    for m in machines:
        try:
            if evaluate_one(session, m.machine_id) is not None:
                emitted += 1
        except Exception as exc:  # noqa: BLE001 — boundary swallow is intentional
            try:
                session.rollback()
            except Exception:  # noqa: BLE001
                pass
            errors.append(f"{m.machine_id}: {exc}")
            log.warning("ai_trigger_escalation tick error: %s", errors[-1])
    return {"machines_evaluated": len(machines), "findings_emitted": emitted, "errors": errors}
