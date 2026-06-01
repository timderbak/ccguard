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
            # Before treating this as a brand-new hook, look for an existing
            # baseline on the same (event, matcher) but with a different
            # command_string. Claude Code allows one hook per (event, matcher)
            # slot, so any matcher+event reuse with a different command means
            # the old command was *replaced*, not added — that's command drift.
            same_slot_other_cmd = session.exec(
                select(HookBaseline).where(
                    HookBaseline.machine_id == machine_id,
                    HookBaseline.event_name == event,
                    HookBaseline.matcher == matcher,
                    HookBaseline.command_string != command,
                    HookBaseline.status.in_(["active", "accepted_drift", "pending"]),
                )
            ).first()

            if same_slot_other_cmd is not None:
                # Command drift: update the existing row in-place, no new row.
                findings.append(_make_finding(
                    machine_id=machine_id,
                    inventory_id=inventory_id,
                    rule_id="hook.rug_pull.command",
                    severity="warn",
                    title=f"Команда хука {event} ({matcher or '*'}) изменилась",
                    description=(
                        f"Было: `{same_slot_other_cmd.command_string[:200]}`\n"
                        f"Стало: `{command[:200]}`\n"
                        "Кто-то менял settings.json вручную или прошла переустановка "
                        "плагина. Это видимое изменение — менее изящная атака, но "
                        "проверь источник."
                    ),
                    payload={
                        "event_name": event, "matcher": matcher,
                        "old_command": same_slot_other_cmd.command_string,
                        "new_command": command,
                        "file_path": hk.command_file_path,
                    },
                ))
                same_slot_other_cmd.command_string = command
                same_slot_other_cmd.file_path = hk.command_file_path
                same_slot_other_cmd.file_content_hash = hk.command_file_hash
                same_slot_other_cmd.fingerprint = new_fp
                same_slot_other_cmd.last_seen_at = now
                session.add(same_slot_other_cmd)
                # Also remove the original slot_key from seen_slot_keys path:
                # the *new* command is what's seen this sync, so the OLD
                # command_string is what should fall into the "missing" sweep
                # at the bottom of the loop. But because we mutated the row to
                # the new command_string in-place, the missing-sweep below
                # would no longer match the old key anyway. Nothing to do.
                continue

            # Truly new slot — record as pending. Emit ``hook.new`` only if any
            # active baseline already exists on this machine; otherwise we're
            # bootstrapping (first sync of a machine that may have 40+ hooks
            # in settings.json already — silent ingestion saves admins from
            # finding-card spam on initial connect).
            has_active = session.exec(
                select(HookBaseline)
                .where(
                    HookBaseline.machine_id == machine_id,
                    HookBaseline.status == "active",
                )
                .limit(1)
            ).first()

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

            if has_active is not None:
                findings.append(_make_finding(
                    machine_id=machine_id,
                    inventory_id=inventory_id,
                    rule_id="hook.new",
                    severity="warn",
                    title=f"Появился новый хук {event} ({matcher or '*'})",
                    description=(
                        f"Новый хук в {hk.source or 'settings.json'}: команда "
                        f"`{command[:200]}`. Источник не подтверждён как baseline. "
                        "Если ты сам ставил — нажми «Принять baseline» в UI. "
                        "Если нет — удали и пересинхронизируй."
                    ),
                    payload={
                        "event_name": event, "matcher": matcher,
                        "command": command[:500], "source": hk.source,
                        "file_path": hk.command_file_path,
                    },
                ))
            continue

        # Existing slot, fingerprint mismatched → file content drifted.
        # ("Command drift" lives in a different slot key — Task 8 handles it.)
        if (existing.file_content_hash or "") != (hk.command_file_hash or ""):
            findings.append(_make_finding(
                machine_id=machine_id,
                inventory_id=inventory_id,
                rule_id="hook.rug_pull.content",
                severity="block",
                title="Содержимое хука изменилось без обновления settings.json",
                description=(
                    f"Скрипт {hk.command_file_path or '<inline>'} для хука {event} "
                    f"({matcher or '*'}) поменялся. Это классический supply chain "
                    "rug pull: команда та же, но payload новый. Проверь источник "
                    "плагина. Если ты сам обновлял — нажми «Принять новый baseline»."
                ),
                payload={
                    "event_name": event, "matcher": matcher,
                    "command": command[:500], "file_path": hk.command_file_path,
                    "old_file_content_hash": existing.file_content_hash,
                    "new_file_content_hash": hk.command_file_hash,
                },
            ))

        # Refresh the slot row in-place. fingerprint/content updated; status
        # is preserved so the admin's prior trust state (active / pending /
        # accepted_drift) survives.
        existing.file_content_hash = hk.command_file_hash
        existing.fingerprint = new_fp
        existing.last_seen_at = now
        existing.file_path = hk.command_file_path
        session.add(existing)
        continue

    for f in findings:
        session.add(f)
    return findings
