"""ATLAS taxonomy seed loader + ТЗ-05 technique→mapping migration (ТЗ-06).

Same hybrid model as ``indicator_seed_service``: a version-controlled vetted
seed loads idempotently at startup. Then ``migrate_indicator_techniques`` moves
the ТЗ-05 scalar ``ThreatIndicator.technique`` attribution into the normalized
``IndicatorTechniqueMapping`` junction (the new source of truth). The scalar
field is left in place (deprecated), so this is additive and safe to re-run.
"""
from __future__ import annotations

import logging
from pathlib import Path

import yaml
from sqlmodel import Session, select

from ccguard.server.db.models import (
    IndicatorTechniqueMapping,
    Technique,
    ThreatIndicator,
)

log = logging.getLogger(__name__)

_ALLOWED_FIELDS = frozenset(
    {
        "technique_id",
        "framework",
        "name",
        "tactic",
        "description",
        "parent_technique",
        "url",
        "in_scope",
        "source",
        "tactic_source",
    }
)
_REQUIRED_FIELDS = ("technique_id", "framework", "name", "tactic")


def default_seed_path() -> Path:
    # ТЗ-08: renamed from atlas_techniques_seed.yaml — now three frameworks
    # (atlas + attack + owasp), not ATLAS-only.
    return Path(__file__).resolve().parent.parent / "data" / "techniques_seed.yaml"


def _read_seed(seed_path: Path) -> list[dict]:
    """Parse the technique seed. Never raises — broken seed → [] + warning."""
    try:
        if not seed_path.exists():
            log.warning("atlas seed: file not found at %s — loading nothing", seed_path)
            return []
        data = yaml.safe_load(seed_path.read_text()) or {}
    except Exception as exc:  # noqa: BLE001 — broken seed must not crash boot
        log.warning("atlas seed: failed to parse %s: %s", seed_path, exc)
        return []
    techniques = data.get("techniques") if isinstance(data, dict) else None
    if not isinstance(techniques, list):
        log.warning("atlas seed: no 'techniques' list in %s", seed_path)
        return []
    return [e for e in techniques if isinstance(e, dict)]


def load_atlas_seed(session: Session, seed_path: Path | None = None) -> int:
    """Idempotently load the technique taxonomy. Returns rows inserted.

    Insert-or-skip on ``technique_id`` (never overwrites admin/Path-2 edits).
    """
    path = seed_path if seed_path is not None else default_seed_path()
    entries = _read_seed(path)
    if not entries:
        return 0

    existing = {r.technique_id for r in session.exec(select(Technique)).all()}
    inserted = 0
    for entry in entries:
        if not all(entry.get(k) for k in _REQUIRED_FIELDS):
            log.warning("atlas seed: skipping entry missing required keys: %r", entry)
            continue
        tid = entry["technique_id"]
        if tid in existing:
            continue
        fields = {k: v for k, v in entry.items() if k in _ALLOWED_FIELDS}
        # ТЗ-09: OWASP ASI is an unordered risk layer, not a kill-chain stage
        # axis — tag it so the chain engine / UI never treat its tactic as an
        # ordered stage. attack/atlas are real kill-chain stages.
        fields.setdefault(
            "tactic_source",
            "risk-layer" if fields.get("framework") == "owasp" else "kill-chain",
        )
        session.add(Technique(**fields))
        existing.add(tid)
        inserted += 1

    if inserted:
        session.commit()
    return inserted


def migrate_indicator_techniques(session: Session) -> int:
    """Move ТЗ-05 ``ThreatIndicator.technique`` scalars into the junction table.

    Idempotent: skips pairs that already exist. A technique referenced by an
    indicator but absent from ``AtlasTechnique`` is logged (seed inconsistency)
    and skipped — never raises. Returns mapping rows created.
    """
    known_techniques = {r.technique_id for r in session.exec(select(Technique)).all()}
    existing_pairs = {
        (m.indicator_id, m.technique_id)
        for m in session.exec(select(IndicatorTechniqueMapping)).all()
    }
    created = 0
    for ind in session.exec(select(ThreatIndicator)).all():
        tid = ind.technique
        if not tid:
            continue
        if tid not in known_techniques:
            log.warning(
                "atlas migrate: indicator %s references unknown technique %r — skipped",
                ind.id, tid,
            )
            continue
        if (ind.id, tid) in existing_pairs:
            continue
        # ТЗ-09 (ТЗ-08 tail): control_type per OWASP rationale taxonomy. A
        # dangerous-command indicator backs a blocking enforce rule → PREV;
        # path/host indicators limit/observe access to an artefact → SCOPE.
        control_type = "PREV" if ind.indicator_type == "dangerous_command" else "SCOPE"
        session.add(
            IndicatorTechniqueMapping(
                indicator_id=ind.id,
                technique_id=tid,
                mapping_source="seed",
                control_type=control_type,
            )
        )
        existing_pairs.add((ind.id, tid))
        created += 1

    if created:
        session.commit()
    return created
