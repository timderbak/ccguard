"""Seed → ThreatIndicator loader (ТЗ-05).

Hybrid model: the vetted core of indicators is version-controlled in
``server/data/threat_indicators_seed.yaml`` (reviewed as code, ships with the
release) and loaded into the ``threatindicator`` table on startup. The table is
the single source of truth for future consumers (detection engines, wired in a
later ТЗ). Path-2 autocollection will instead INSERT rows directly with
``status="pending"``.

Load semantics (mirrors ``settings_service`` seeds):
- Idempotent insert-or-skip on ``(indicator_type, value, source)`` — a restart
  never duplicates, and never overwrites a row an admin edited in the DB.
- Seed rows are stamped ``status="active"`` (vetted) and ``enabled=True``.
- A missing or corrupt seed file logs a warning and loads nothing; the server
  still starts (the store is additive, not load-bearing for boot).
"""
from __future__ import annotations

import logging
from pathlib import Path

import yaml
from sqlmodel import Session, select

from ccguard.server.db.models import ThreatIndicator

log = logging.getLogger(__name__)

# Fields a seed entry may set; anything else in the YAML is ignored defensively.
_ALLOWED_FIELDS = frozenset(
    {
        "indicator_type",
        "value",
        "value_kind",
        "source",
        "source_ref",
        "technique",
        "tactic",
        "weight",
        "platform_relevant",
        "description",
    }
)
_REQUIRED_FIELDS = ("indicator_type", "value", "source")


def default_seed_path() -> Path:
    """Path to the version-controlled seed shipped in the package."""
    return Path(__file__).resolve().parent.parent / "data" / "threat_indicators_seed.yaml"


def _read_seed(seed_path: Path) -> list[dict]:
    """Parse the seed file into a list of entry dicts. Never raises.

    Missing file, unparseable YAML, or wrong shape → ``[]`` + a warning, so a
    broken seed can never block server startup.
    """
    try:
        if not seed_path.exists():
            log.warning("indicator seed: file not found at %s — loading nothing", seed_path)
            return []
        data = yaml.safe_load(seed_path.read_text()) or {}
    except Exception as exc:  # noqa: BLE001 — broken seed must not crash boot
        log.warning("indicator seed: failed to parse %s: %s", seed_path, exc)
        return []
    indicators = data.get("indicators") if isinstance(data, dict) else None
    if not isinstance(indicators, list):
        log.warning("indicator seed: no 'indicators' list in %s", seed_path)
        return []
    return [e for e in indicators if isinstance(e, dict)]


def load_seed(session: Session, seed_path: Path | None = None) -> int:
    """Idempotently load seed indicators into the table. Returns rows inserted.

    Existing ``(indicator_type, value, source)`` triples are skipped (never
    overwritten). All seed rows are stamped ``status="active"``.
    """
    path = seed_path if seed_path is not None else default_seed_path()
    entries = _read_seed(path)
    if not entries:
        return 0

    existing = {
        (r.indicator_type, r.value, r.source)
        for r in session.exec(select(ThreatIndicator)).all()
    }

    inserted = 0
    for entry in entries:
        if not all(entry.get(k) for k in _REQUIRED_FIELDS):
            log.warning("indicator seed: skipping entry missing required keys: %r", entry)
            continue
        key = (entry["indicator_type"], entry["value"], entry["source"])
        if key in existing:
            continue
        fields = {k: v for k, v in entry.items() if k in _ALLOWED_FIELDS}
        session.add(ThreatIndicator(status="active", enabled=True, **fields))
        existing.add(key)
        inserted += 1

    if inserted:
        session.commit()
    return inserted
