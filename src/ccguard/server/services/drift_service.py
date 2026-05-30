"""Config-drift detector (Vector 2a).

Catches the supply-chain attack class where an attacker doesn't run any
suspicious command — they just *modify the AI agent's config*. New skill
appears, a hook's command file hash changes, an MCP server's args grow a
``--evil`` flag. Classic EDR doesn't see this; per-event signal detection
doesn't either; only inventory diff catches it.

How:

1. For every warm machine, compare the latest two ``InventorySnapshot`` rows.
2. Diff sensitive collections (skills, agents, hooks, mcp_servers) by their
   stable identity (``name`` or composite) and content fingerprint.
3. Aggregate all changes for one machine into a single ``persist.agent_config``
   finding (severity=warn) so one drift event = one alert in the queue.
4. Same-UTC-day dedup mirrors the other ticks.

Chained into the scheduler tick after ``sequence_tick``.
"""
from __future__ import annotations

import json
import logging
from datetime import UTC, datetime
from typing import Any

from sqlalchemy import func
from sqlmodel import Session, select

from ccguard.server.db.models import (
    FindingRecord,
    InventorySnapshot,
    Machine,
    MachineBaseline,
)

log = logging.getLogger(__name__)

DRIFT_RULE_ID: str = "persist.agent_config"


def _machine_is_warm(session: Session, machine_id: str) -> bool:
    stmt = (
        select(MachineBaseline)
        .where(MachineBaseline.machine_id == machine_id)
        .where(MachineBaseline.baseline_ready == True)  # noqa: E712
        .limit(1)
    )
    return session.exec(stmt).first() is not None


def _same_day_drift_exists(
    session: Session, machine_id: str, today_utc: datetime
) -> bool:
    today_iso = today_utc.date().isoformat()
    stmt = (
        select(FindingRecord)
        .where(FindingRecord.machine_id == machine_id)
        .where(FindingRecord.rule_id == DRIFT_RULE_ID)
        .where(func.date(FindingRecord.discovered_at) == today_iso)
        .limit(1)
    )
    return session.exec(stmt).first() is not None


def _last_two_snapshots(
    session: Session, machine_id: str
) -> tuple[dict[str, Any], dict[str, Any]] | None:
    """Return (previous, current) inventory payloads, or None if <2 exist."""
    stmt = (
        select(InventorySnapshot)
        .where(InventorySnapshot.machine_id == machine_id)
        .order_by(InventorySnapshot.received_at.desc())  # type: ignore[attr-defined]
        .limit(2)
    )
    rows = list(session.exec(stmt))
    if len(rows) < 2:
        return None
    try:
        prev = json.loads(rows[1].payload_json)
        cur = json.loads(rows[0].payload_json)
    except (ValueError, TypeError):
        return None
    if not isinstance(prev, dict) or not isinstance(cur, dict):
        return None
    return prev, cur


def _items_by_key(
    items: list[dict[str, Any]] | None, key_fn
) -> dict[str, dict[str, Any]]:
    out: dict[str, dict[str, Any]] = {}
    for it in items or []:
        if not isinstance(it, dict):
            continue
        try:
            out[key_fn(it)] = it
        except (KeyError, TypeError):
            continue
    return out


def _hook_key(h: dict[str, Any]) -> str:
    # Hooks have no natural id; composite of event + type + command/url stays
    # stable enough that a re-add of the same hook isn't flagged as drift.
    return f"{h.get('event')}:{h.get('type')}:{h.get('command') or h.get('url') or ''}"


def _diff_named(
    kind: str,
    prev_items: list[dict[str, Any]] | None,
    cur_items: list[dict[str, Any]] | None,
    *,
    key_fn,
    fingerprint_fn,
) -> list[dict[str, Any]]:
    """Generic diff for a list of dicts keyed by an identity function."""
    prev_by_key = _items_by_key(prev_items, key_fn)
    cur_by_key = _items_by_key(cur_items, key_fn)
    changes: list[dict[str, Any]] = []
    for key, cur in cur_by_key.items():
        if key not in prev_by_key:
            changes.append({"kind": f"{kind}_added", "name": key})
            continue
        if fingerprint_fn(prev_by_key[key]) != fingerprint_fn(cur):
            changes.append({"kind": f"{kind}_modified", "name": key})
    for key in prev_by_key.keys() - cur_by_key.keys():
        changes.append({"kind": f"{kind}_removed", "name": key})
    return changes


def diff_inventory(prev: dict[str, Any], cur: dict[str, Any]) -> list[dict[str, Any]]:
    """Return all sensitive drift events between two inventory payloads."""
    changes: list[dict[str, Any]] = []
    changes += _diff_named(
        "skill",
        prev.get("skills"),
        cur.get("skills"),
        key_fn=lambda s: s["name"],
        fingerprint_fn=lambda s: s.get("dir_hash"),
    )
    changes += _diff_named(
        "agent",
        prev.get("agents"),
        cur.get("agents"),
        key_fn=lambda a: a["name"],
        fingerprint_fn=lambda a: (a.get("file_hash"), tuple(a.get("tools") or []), a.get("model")),
    )
    changes += _diff_named(
        "hook",
        prev.get("hooks"),
        cur.get("hooks"),
        key_fn=_hook_key,
        fingerprint_fn=lambda h: h.get("command_file_hash"),
    )
    changes += _diff_named(
        "mcp",
        prev.get("mcp_servers"),
        cur.get("mcp_servers"),
        key_fn=lambda m: m["name"],
        fingerprint_fn=lambda m: (
            m.get("transport"), m.get("command"),
            tuple(m.get("args") or []), m.get("url"),
        ),
    )
    return changes


def evaluate_one(session: Session, machine_id: str) -> FindingRecord | None:
    if not _machine_is_warm(session, machine_id):
        return None
    pair = _last_two_snapshots(session, machine_id)
    if pair is None:
        return None
    prev, cur = pair
    changes = diff_inventory(prev, cur)
    if not changes:
        return None

    now = datetime.now(UTC)
    if _same_day_drift_exists(session, machine_id, now):
        return None

    payload = {"changes": changes, "change_count": len(changes)}
    finding = FindingRecord(
        machine_id=machine_id,
        inventory_id=None,
        rule_id=DRIFT_RULE_ID,
        severity="warn",
        discovered_at=now,
        payload_json=json.dumps(payload, ensure_ascii=False),
    )
    session.add(finding)
    session.commit()
    session.refresh(finding)
    return finding


def tick(session: Session) -> dict[str, object]:
    """Detect config drift across every warm machine. Mirrors risk_service.tick."""
    machines = list(session.exec(select(Machine)))
    emitted = 0
    errors: list[str] = []
    for m in machines:
        try:
            if evaluate_one(session, m.machine_id) is not None:
                emitted += 1
        except Exception as exc:  # noqa: BLE001
            try:
                session.rollback()
            except Exception:  # noqa: BLE001
                pass
            errors.append(f"{m.machine_id}: {exc}")
            log.warning("drift tick error: %s", errors[-1])
    return {
        "machines_evaluated": len(machines),
        "findings_emitted": emitted,
        "errors": errors,
    }
