"""KV settings accessor + seeder for Plan 03-01 (D-04).

Public surface:

- :func:`get_setting` — read a key, returning ``None`` if absent.
- :func:`set_setting` — upsert a key (admin path).
- :func:`seed_llm_settings` — idempotent first-startup seed of
  ``llm_scanner_enabled`` and ``daily_call_budget`` defaults; preserves any
  admin-modified values across re-seeds.

The seeder is called from the server lifespan immediately after ``init_db``
so admin-tunable knobs are guaranteed to exist before any LLM-scanner code
path reads them. Phase 1+2 startup paths are untouched.
"""

from __future__ import annotations

import logging

from sqlmodel import Session, select

from ccguard.server.db.models import SettingsRecord

_log = logging.getLogger("ccguard.server.settings")
_budget_parse_warned: set[str] = set()

# Locked defaults per 03-CONTEXT.md / Plan 03-01.
_LLM_SETTINGS_DEFAULTS: dict[str, str] = {
    "llm_scanner_enabled": "false",
    "daily_call_budget": "100",
}


def get_setting(session: Session, key: str) -> str | None:
    """Return the stored value for ``key`` or ``None`` if the key is absent."""
    row = session.get(SettingsRecord, key)
    return None if row is None else row.value


def set_setting(session: Session, key: str, value: str) -> None:
    """Upsert ``key`` → ``value`` and commit."""
    from datetime import UTC, datetime

    row = session.get(SettingsRecord, key)
    if row is None:
        row = SettingsRecord(key=key, value=value)
    else:
        row.value = value
        row.updated_at = datetime.now(UTC)
    session.add(row)
    session.commit()


def parse_budget(raw: str | None) -> int:
    """Parse ``daily_call_budget`` to int, returning 0 on absence or corruption.

    WR-04: previously each caller did ``int(raw or "0")`` in a bare try/except
    that silently coerced bad input to 0, leaving operators unable to spot a
    corrupt KV value. We now warn-log once per distinct bad value so the
    operator sees it in journalctl without flooding the log on repeated reads.
    """
    if not raw:
        return 0
    try:
        return int(raw)
    except ValueError:
        if raw not in _budget_parse_warned:
            _budget_parse_warned.add(raw)
            _log.warning(
                "daily_call_budget value %r is not an int; treating as 0", raw
            )
        return 0


def seed_llm_settings(session: Session) -> None:
    """Idempotently insert the two LLM-scanner KV defaults.

    Safe to call on every server startup: existing keys (including
    admin-modified values) are left untouched; only missing keys are inserted.
    """
    existing_keys = {
        r.key
        for r in session.exec(
            select(SettingsRecord).where(
                SettingsRecord.key.in_(list(_LLM_SETTINGS_DEFAULTS.keys()))
            )
        ).all()
    }
    inserted = False
    for key, default_value in _LLM_SETTINGS_DEFAULTS.items():
        if key in existing_keys:
            continue
        session.add(SettingsRecord(key=key, value=default_value))
        inserted = True
    if inserted:
        session.commit()
