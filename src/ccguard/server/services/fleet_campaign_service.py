"""Fleet-scope supply-chain campaign correlator — moat depth.

Every other correlator (sequence/chain/slow_chain/ai_trigger_escalation) is
MACHINE-scoped. But the signature org-wide attack on AI-agent fleets is one
supply-chain compromise — a single poisoned/rug-pulled MCP server, or a drifted
skill/hook/agent — pushed to MANY developer machines at once. Per-endpoint each
hit may sit under threshold and reads as an isolated drift; no machine-scoped
engine ever says "the SAME compromised component just landed on N machines".

This service closes exactly the blind spot the audit named: ``is_divergent``
flags hash DIVERGENCE, so an IDENTICAL poison on every machine
(``len(versions)==1``) is invisible as a divergence — yet it is the worst case
(a coordinated campaign). Here we group the AI-origin trigger findings by the
COMPROMISED COMPONENT'S IDENTITY (the MCP server / skill / hook / agent name,
carried in the finding payload) and fire when one identity appears across
``>= min_machines`` DISTINCT machines within a window → ``ioa.fleet_campaign``
(critical). This is the org-wide view a per-endpoint EDR structurally cannot
build.

Org-scoped (single-tenant): the finding is attached to the sentinel machine_id
``_fleet``. Mirrors the slow_chain/ai_trigger tick contract (same-UTC-day dedup,
per-identity, tunable via SettingsRecord). NB (TOFU caveat): a machine whose
FIRST sighting of a component was already the poisoned version never raised a
drift, so it does not count here — the campaign view spans the machines that had
a clean baseline and detected the change.
"""
from __future__ import annotations

import json
import logging
from collections import defaultdict
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta

from sqlmodel import Session, select

from ccguard.server.db.models import FindingRecord
from ccguard.server.services import settings_service
from ccguard.server.services._utc import aware_utc

log = logging.getLogger(__name__)

RULE_ID = "ioa.fleet_campaign"
SEVERITY = "critical"
FLEET_MACHINE_ID = "_fleet"  # org-scope sentinel (cf. "_server" for LLM findings)

# AI-origin supply-chain trigger families that carry a stable COMPONENT IDENTITY
# (the name) in their payload — so the same component can be tracked across the
# fleet. PI / llm.scan are per-event (no cross-machine component identity) and
# are deliberately excluded.
TRIGGER_RULE_PREFIXES: tuple[str, ...] = (
    "mcp.rug_pull",
    "skill.rug_pull",
    "agent.rug_pull",
    "hook.rug_pull",
    "skill.drift",
    "agent.drift",
    "hook.content",
)

# Payload keys that may hold the component's stable name, in priority order.
_IDENTITY_KEYS: tuple[str, ...] = ("mcp_name", "skill_name", "agent_name", "hook_name", "matched_value", "name")

DEFAULT_WINDOW_HOURS: float = 7 * 24.0
DEFAULT_MIN_MACHINES: int = 2
SETTING_WINDOW_HOURS = "fleet_campaign.window_hours"
SETTING_MIN_MACHINES = "fleet_campaign.min_machines"


@dataclass(frozen=True)
class Trigger:
    machine_id: str
    family: str          # mcp / skill / agent / hook
    identity: str        # the component name
    rule_id: str
    ts: datetime


@dataclass(frozen=True)
class Campaign:
    family: str
    identity: str
    machines: tuple[str, ...]
    first_seen: datetime
    last_seen: datetime
    rule_ids: tuple[str, ...]


# --- Pure kernel -----------------------------------------------------------


def _family_of(rule_id: str) -> str:
    return rule_id.split(".", 1)[0] if rule_id else ""


def detect_campaigns(triggers: list[Trigger], *, min_machines: int) -> list[Campaign]:
    """Group triggers by (family, identity); a campaign is one such group that
    spans ``>= min_machines`` DISTINCT machines. Pure — no I/O."""
    groups: dict[tuple[str, str], list[Trigger]] = defaultdict(list)
    for t in triggers:
        if not t.identity:
            continue
        groups[(t.family, t.identity)].append(t)

    out: list[Campaign] = []
    for (family, identity), ts in groups.items():
        machines = sorted({t.machine_id for t in ts})
        if len(machines) < min_machines:
            continue
        stamps = sorted(t.ts for t in ts)
        out.append(
            Campaign(
                family=family,
                identity=identity,
                machines=tuple(machines),
                first_seen=stamps[0],
                last_seen=stamps[-1],
                rule_ids=tuple(sorted({t.rule_id for t in ts})),
            )
        )
    # most-spread first (biggest blast radius)
    out.sort(key=lambda c: len(c.machines), reverse=True)
    return out


# --- Orchestrator ----------------------------------------------------------


def _tunable_float(session: Session, key: str, default: float) -> float:
    raw = settings_service.get_setting(session, key)
    if raw is None:
        return default
    try:
        return float(raw)
    except (TypeError, ValueError):
        log.warning("fleet_campaign: bad %s=%r, using default", key, raw)
        return default


def _is_trigger(rule_id: str) -> bool:
    return any(rule_id.startswith(p) for p in TRIGGER_RULE_PREFIXES)


def _identity_of(payload_json: str) -> str:
    try:
        payload = json.loads(payload_json)
    except (TypeError, ValueError):
        return ""
    if not isinstance(payload, dict):
        return ""
    for k in _IDENTITY_KEYS:
        v = payload.get(k)
        if isinstance(v, str) and v.strip():
            return v.strip()
    return ""


def _load_triggers(session: Session, since: datetime) -> list[Trigger]:
    """Load AI-origin trigger findings across ALL machines in the window."""
    stmt = select(FindingRecord).where(FindingRecord.discovered_at >= since)
    out: list[Trigger] = []
    for row in session.exec(stmt):
        if row.machine_id == FLEET_MACHINE_ID or not _is_trigger(row.rule_id):
            continue
        identity = _identity_of(row.payload_json or "")
        if not identity:
            continue
        out.append(
            Trigger(
                machine_id=row.machine_id,
                family=_family_of(row.rule_id),
                identity=identity,
                rule_id=row.rule_id,
                ts=aware_utc(row.discovered_at),
            )
        )
    return out


def _same_day_finding_exists(session: Session, identity: str, today_utc: datetime) -> bool:
    from sqlalchemy import func

    today_iso = today_utc.date().isoformat()
    stmt = (
        select(FindingRecord)
        .where(FindingRecord.machine_id == FLEET_MACHINE_ID)
        .where(FindingRecord.rule_id == RULE_ID)
        .where(func.date(FindingRecord.discovered_at) == today_iso)
    )
    for row in session.exec(stmt):
        try:
            if json.loads(row.payload_json).get("identity") == identity:
                return True
        except (TypeError, ValueError):
            continue
    return False


def evaluate(session: Session) -> list[FindingRecord]:
    """Emit ``ioa.fleet_campaign`` for each component compromised across
    ``>= min_machines`` machines in the window. Returns the new findings."""
    window_hours = _tunable_float(session, SETTING_WINDOW_HOURS, DEFAULT_WINDOW_HOURS)
    min_machines = int(_tunable_float(session, SETTING_MIN_MACHINES, DEFAULT_MIN_MACHINES))
    now = datetime.now(UTC)
    since = now - timedelta(hours=window_hours)

    triggers = _load_triggers(session, since)
    campaigns = detect_campaigns(triggers, min_machines=max(2, min_machines))

    emitted: list[FindingRecord] = []
    for c in campaigns:
        if _same_day_finding_exists(session, c.identity, now):
            continue
        gap_h = round((c.last_seen - c.first_seen).total_seconds() / 3600.0, 2)
        payload = {
            "identity": c.identity,
            "family": c.family,
            "machine_count": len(c.machines),
            "machines": list(c.machines),
            "rule_ids": list(c.rule_ids),
            "first_seen": c.first_seen.isoformat(),
            "last_seen": c.last_seen.isoformat(),
            "spread_hours": gap_h,
            "window_hours": window_hours,
            "narrative": (
                f"Один и тот же {c.family}-компонент '{c.identity}' скомпрометирован "
                f"на {len(c.machines)} машинах за {gap_h}ч — это ОРГ-УРОВЕНЬ кампания "
                f"(supply-chain), которую per-endpoint EDR не агрегирует."
            ),
        }
        # mirror narrative into ``rationale`` so the findings-list row surfaces
        # the story without a dedicated machine page (_fleet has none).
        payload["rationale"] = payload["narrative"]
        finding = FindingRecord(
            machine_id=FLEET_MACHINE_ID,
            inventory_id=None,
            rule_id=RULE_ID,
            severity=SEVERITY,
            discovered_at=now,
            payload_json=json.dumps(payload, ensure_ascii=False, allow_nan=False),
        )
        session.add(finding)
        emitted.append(finding)
    if emitted:
        session.commit()
        for f in emitted:
            session.refresh(f)
    return emitted


def tick(session: Session) -> dict[str, object]:
    """Run the fleet-campaign sweep once over the whole org. Mirrors slow_chain."""
    try:
        emitted = evaluate(session)
        return {"campaigns_emitted": len(emitted), "errors": []}
    except Exception as exc:  # noqa: BLE001 — boundary swallow is intentional
        try:
            session.rollback()
        except Exception:  # noqa: BLE001
            pass
        log.warning("fleet_campaign tick error: %s", exc)
        return {"campaigns_emitted": 0, "errors": [str(exc)]}
