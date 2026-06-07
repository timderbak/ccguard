"""ТЗ-08 taxonomy seed loaders: cross-framework crosswalk + detector registry.

Same hybrid model as ``atlas_seed_service`` / ``indicator_seed_service``:
version-controlled vetted seeds load idempotently at startup. These loaders add
the two pieces ТЗ-08 introduces on top of the technique catalog:

  * ``load_crosswalk_seed`` — horizontal ``≈`` links between frameworks
    (``technique_crosswalk_seed.yaml``).
  * ``load_detector_seed`` — registers the EXISTING correlation detectors and
    binds them to techniques (``detector_mappings_seed.yaml``). The detector
    code is NOT touched; this only records detector_key → technique so the
    coverage map can see correlations, not just indicators.

Both are insert-or-skip (idempotent) and never raise: a broken/missing seed
logs a warning and loads nothing, so startup is never blocked.
"""
from __future__ import annotations

import logging
from pathlib import Path

import yaml
from sqlmodel import Session, select

from ccguard.server.db.models import (
    Detector,
    DetectorTechniqueMapping,
    TechniqueCrosswalk,
)

log = logging.getLogger(__name__)

_DATA_DIR = Path(__file__).resolve().parent.parent / "data"

_CROSSWALK_FIELDS = frozenset({"technique_id_a", "technique_id_b", "relation", "source"})
_CROSSWALK_REQUIRED = ("technique_id_a", "technique_id_b")

_DETECTOR_FIELDS = frozenset({"detector_key", "name", "kind", "description", "rule_ids"})
_DETECTOR_REQUIRED = ("detector_key", "name")

_MAPPING_FIELDS = frozenset(
    {"detector_key", "technique_id", "framework", "control_type", "relevance",
     "confidence", "mapping_source"}
)
_MAPPING_REQUIRED = ("detector_key", "technique_id", "framework")


def default_crosswalk_path() -> Path:
    return _DATA_DIR / "technique_crosswalk_seed.yaml"


def default_detector_path() -> Path:
    return _DATA_DIR / "detector_mappings_seed.yaml"


def _read_yaml(seed_path: Path, key: str) -> list[dict]:
    """Parse a seed file; never raises. Broken/missing → [] + warning."""
    try:
        if not seed_path.exists():
            log.warning("taxonomy seed: file not found at %s — loading nothing", seed_path)
            return []
        data = yaml.safe_load(seed_path.read_text()) or {}
    except Exception as exc:  # noqa: BLE001 — broken seed must not crash boot
        log.warning("taxonomy seed: failed to parse %s: %s", seed_path, exc)
        return []
    items = data.get(key) if isinstance(data, dict) else None
    if not isinstance(items, list):
        log.warning("taxonomy seed: no '%s' list in %s", key, seed_path)
        return []
    return [e for e in items if isinstance(e, dict)]


def load_crosswalk_seed(session: Session, seed_path: Path | None = None) -> int:
    """Idempotently load cross-framework ``≈`` links. Returns rows inserted.

    Insert-or-skip on the unordered pair {a, b}: the relation is symmetric, so
    (a, b) and (b, a) are the same link and only one is stored.
    """
    path = seed_path if seed_path is not None else default_crosswalk_path()
    entries = _read_yaml(path, "crosswalks")
    if not entries:
        return 0

    existing: set[frozenset[str]] = {
        frozenset((r.technique_id_a, r.technique_id_b))
        for r in session.exec(select(TechniqueCrosswalk)).all()
    }
    inserted = 0
    for entry in entries:
        if not all(entry.get(k) for k in _CROSSWALK_REQUIRED):
            log.warning("crosswalk seed: skipping entry missing keys: %r", entry)
            continue
        pair = frozenset((entry["technique_id_a"], entry["technique_id_b"]))
        if pair in existing:
            continue
        fields = {k: v for k, v in entry.items() if k in _CROSSWALK_FIELDS}
        session.add(TechniqueCrosswalk(**fields))
        existing.add(pair)
        inserted += 1

    if inserted:
        session.commit()
    return inserted


def load_detector_seed(session: Session, seed_path: Path | None = None) -> int:
    """Idempotently register detectors + bind them to techniques.

    Returns the number of NEW rows (detectors + mappings) inserted. Insert-or-
    skip: detectors on ``detector_key``, mappings on
    ``(detector_key, technique_id)``.
    """
    path = seed_path if seed_path is not None else default_detector_path()
    detectors = _read_yaml(path, "detectors")
    mappings = _read_yaml(path, "mappings")
    if not detectors and not mappings:
        return 0

    inserted = 0

    existing_detectors = {r.detector_key for r in session.exec(select(Detector)).all()}
    for entry in detectors:
        if not all(entry.get(k) for k in _DETECTOR_REQUIRED):
            log.warning("detector seed: skipping detector missing keys: %r", entry)
            continue
        key = entry["detector_key"]
        if key in existing_detectors:
            continue
        fields = {k: v for k, v in entry.items() if k in _DETECTOR_FIELDS}
        session.add(Detector(**fields))
        existing_detectors.add(key)
        inserted += 1

    existing_pairs = {
        (m.detector_key, m.technique_id)
        for m in session.exec(select(DetectorTechniqueMapping)).all()
    }
    for entry in mappings:
        if not all(entry.get(k) for k in _MAPPING_REQUIRED):
            log.warning("detector seed: skipping mapping missing keys: %r", entry)
            continue
        pair = (entry["detector_key"], entry["technique_id"])
        if pair in existing_pairs:
            continue
        fields = {k: v for k, v in entry.items() if k in _MAPPING_FIELDS}
        session.add(DetectorTechniqueMapping(**fields))
        existing_pairs.add(pair)
        inserted += 1

    if inserted:
        session.commit()
    return inserted
