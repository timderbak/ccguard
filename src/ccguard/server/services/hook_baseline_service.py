"""TOFU baseline + drift detection for Claude Code hooks.

Sibling of :mod:`ccguard.server.services.mcp_baseline_service`; same overall
pattern (composite fingerprint, slot-based lookup, accept-flow), different
identity composition.

Design: ``docs/superpowers/specs/2026-06-01-hooks-tofu-baseline-design.md``
"""

from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone

from sqlmodel import Session, select

from ccguard.schemas.inventory import HookEntry
from ccguard.server.db.models import FindingRecord, HookBaseline

# Sentinel that lets us distinguish "no file content hash (couldn't read /
# inline command)" from "explicit empty content hash". The empty-string case
# is reserved for inline shell commands; None means we have no information.
_NONE_SENTINEL = "\x00NONE\x00"


def compute_fingerprint(
    event_name: str,
    matcher: str,
    command_string: str,
    file_content_hash: str | None,
) -> str:
    """Composite sha256 hex (64 chars).

    Four pipe-separated components: event_name, matcher, command_string,
    and either the file_content_hash or a sentinel meaning "no hash available".

    The sentinel makes None and "" distinct so an inline ``bash -c`` hook
    (file_content_hash == "" by convention) won't share a fingerprint with
    a hook whose shim couldn't be read (file_content_hash is None).
    """
    fh = _NONE_SENTINEL if file_content_hash is None else file_content_hash
    raw = f"{event_name}|{matcher}|{command_string}|{fh}".encode("utf-8")
    return hashlib.sha256(raw).hexdigest()


# --- Detection -------------------------------------------------------------


def _now() -> datetime:
    # Repo convention for HookBaseline rows: naive UTC datetime (matches the
    # field type on the SQLModel — no tzinfo so SQLite stores it cleanly).
    return datetime.now(timezone.utc).replace(tzinfo=None)


def _make_finding(
    *,
    machine_id: str,
    inventory_id: int | None,
    rule_id: str,
    severity: str,
    title: str,
    description: str,
    payload: dict,
) -> FindingRecord:
    """Mirror :func:`mcp_baseline_service._make_finding`: title/description
    are persisted inside ``payload_json`` (the FindingRecord table itself has
    no such columns)."""
    payload_full = {
        "rule_id": rule_id,
        "severity": severity,
        "title": title,
        "description": description,
        **payload,
    }
    return FindingRecord(
        machine_id=machine_id,
        inventory_id=inventory_id,
        rule_id=rule_id,
        severity=severity,
        discovered_at=_now(),
        payload_json=json.dumps(payload_full, ensure_ascii=False),
    )


def update_and_detect(
    session: Session,
    machine_id: str,
    current_hooks: list[HookEntry],
    *,
    inventory_id: int | None = None,
) -> list[FindingRecord]:
    """Reconcile current sync against :class:`HookBaseline`; return findings
    (uncommitted — caller commits as part of the inventory POST transaction).

    Side effects: creates / updates :class:`HookBaseline` rows. Findings are
    also added to the session so they share the surrounding commit.
    """
    now = _now()
    findings: list[FindingRecord] = []
    seen_slot_keys: set[tuple[str, str, str]] = set()

    for hk in current_hooks:
        event = hk.event
        matcher = hk.matcher or ""
        command = hk.command or ""
        slot_key = (event, matcher, command)
        seen_slot_keys.add(slot_key)
        new_fp = compute_fingerprint(event, matcher, command, hk.command_file_hash)

        existing: HookBaseline | None = session.exec(
            select(HookBaseline).where(
                HookBaseline.machine_id == machine_id,
                HookBaseline.event_name == event,
                HookBaseline.matcher == matcher,
                HookBaseline.command_string == command,
            )
        ).one_or_none()

        if existing is not None and existing.fingerprint == new_fp:
            existing.last_seen_at = now
            if existing.status == "missing":
                # Hook came back; transparent recovery, no finding.
                existing.status = "active"
            session.add(existing)
            continue

        if existing is None:
            # New slot — record as pending; bootstrap-aware emit added in Task 6.
            row = HookBaseline(
                machine_id=machine_id,
                event_name=event,
                matcher=matcher,
                command_string=command,
                file_path=hk.command_file_path,
                file_content_hash=hk.command_file_hash,
                fingerprint=new_fp,
                status="pending",
                first_seen_at=now,
                last_seen_at=now,
            )
            session.add(row)
            continue

        # Other drift branches (content / command / unreadable) added Tasks 7–10.

    for f in findings:
        session.add(f)
    return findings
