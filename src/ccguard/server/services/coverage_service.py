"""Coverage queries over the ТЗ-08 taxonomy.

Pure relational SQL over the technique catalog and its TWO kinds of detection:

  * INDICATORS — artefact rules (path/command/host) linked via
    ``IndicatorTechniqueMapping``; usually SCOPE/PREV controls.
  * CORRELATIONS — existing behavioral detectors (staging_chain, exfil_sequence,
    external_trigger, rug_pull_tofu, heartbeat_silent) registered in
    ``Detector`` and bound via ``DetectorTechniqueMapping``; DETECT controls.

A technique is *covered* when it has an ENABLED+ACTIVE indicator OR a registered
detector bound to it (with parent rollup). Seeing detectors — not just indicators
— is what fixes the "zero AML coverage" paradox (ТЗ-08): AML.T0051 / ASI01 (IPI)
are covered by correlation, never by an indicator.

Out-of-scope techniques (``in_scope=False``: model/training-internal) are
excluded from gaps and totals so the map shows honest holes, not noise.
"""
from __future__ import annotations

import logging

from sqlalchemy import or_
from sqlmodel import Session, select

from ccguard.server.db.models import (
    Detector,
    DetectorTechniqueMapping,
    IndicatorTechniqueMapping,
    Technique,
    TechniqueCrosswalk,
    ThreatIndicator,
)

log = logging.getLogger(__name__)

# Auto-mappings created by the remap heuristic are deliberately low-confidence
# and tagged so they are distinguishable from vetted seed links (and reviewable).
_AUTO_CONFIDENCE = 0.3


# --------------------------------------------------------------------------- #
# Internal coverage sets                                                       #
# --------------------------------------------------------------------------- #
def _indicator_covered_ids(session: Session) -> set[str]:
    """technique_ids with at least one enabled+active INDICATOR mapped."""
    rows = session.exec(
        select(IndicatorTechniqueMapping.technique_id)
        .join(ThreatIndicator, ThreatIndicator.id == IndicatorTechniqueMapping.indicator_id)
        .where(ThreatIndicator.enabled == True)  # noqa: E712
        .where(ThreatIndicator.status == "active")
    ).all()
    return set(rows)


# Backward-compatible alias (was the only coverage source through ТЗ-06).
_directly_covered_ids = _indicator_covered_ids


def _detector_covered_ids(session: Session) -> set[str]:
    """technique_ids with at least one registered correlation DETECTOR bound.

    Joins through :class:`Detector` so an orphan mapping (no registered detector)
    never counts as coverage.
    """
    rows = session.exec(
        select(DetectorTechniqueMapping.technique_id)
        .join(Detector, Detector.detector_key == DetectorTechniqueMapping.detector_key)
    ).all()
    return set(rows)


def _direct_covered_ids(session: Session) -> set[str]:
    """Union of indicator AND detector coverage — the two detection types."""
    return _indicator_covered_ids(session) | _detector_covered_ids(session)


def _effective_covered_ids(session: Session) -> set[str]:
    """Direct coverage (indicators ∪ detectors) PLUS rollup: a parent technique
    counts as covered when any of its sub-techniques is covered (covering
    T1552.001 covers T1552). Otherwise a fully-detected parent shows up as a gap
    purely because detection attaches to its sub-techniques — a false hole.
    """
    direct = _direct_covered_ids(session)
    if not direct:
        return set()
    covered = set(direct)
    for tech in session.exec(select(Technique)).all():
        if tech.parent_technique and tech.technique_id in direct:
            covered.add(tech.parent_technique)
    return covered


# --------------------------------------------------------------------------- #
# Public coverage queries                                                      #
# --------------------------------------------------------------------------- #
def techniques_covered(session: Session) -> list[Technique]:
    """Techniques we actually detect (indicator OR detector, with parent rollup)."""
    covered = _effective_covered_ids(session)
    if not covered:
        return []
    return list(
        session.exec(select(Technique).where(Technique.technique_id.in_(covered))).all()
    )


def techniques_uncovered(session: Session) -> list[Technique]:
    """Coverage gaps: IN-SCOPE techniques with no (effective) coverage.

    Out-of-scope techniques (model/training-internal, an endpoint EDR can't
    cover) are excluded — they are not honest gaps, just noise on the map.
    """
    covered = _effective_covered_ids(session)
    stmt = select(Technique).where(Technique.in_scope == True)  # noqa: E712
    if covered:
        stmt = stmt.where(Technique.technique_id.not_in(covered))
    return list(session.exec(stmt).all())


def coverage_by_tactic(session: Session) -> dict[str, dict[str, int]]:
    """Per-tactic summary {tactic: {covered, total}} over IN-SCOPE techniques,
    counting parent rollup as covered."""
    covered = _effective_covered_ids(session)
    out: dict[str, dict[str, int]] = {}
    for tech in session.exec(select(Technique)).all():
        if not tech.in_scope:
            continue  # out-of-scope techniques don't count toward the map
        bucket = out.setdefault(tech.tactic, {"covered": 0, "total": 0})
        bucket["total"] += 1
        if tech.technique_id in covered:
            bucket["covered"] += 1
    return out


# --------------------------------------------------------------------------- #
# ТЗ-08: control-type breakdown + per-technique detail                         #
# --------------------------------------------------------------------------- #
def _control_pairs(session: Session) -> list[tuple[str, str]]:
    """(technique_id, control_type) for every active indicator + registered
    detector binding. The raw evidence behind the control-type breakdown."""
    pairs: list[tuple[str, str]] = []
    ind_rows = session.exec(
        select(IndicatorTechniqueMapping.technique_id, IndicatorTechniqueMapping.control_type)
        .join(ThreatIndicator, ThreatIndicator.id == IndicatorTechniqueMapping.indicator_id)
        .where(ThreatIndicator.enabled == True)  # noqa: E712
        .where(ThreatIndicator.status == "active")
    ).all()
    pairs.extend((tid, ct) for tid, ct in ind_rows)
    det_rows = session.exec(
        select(DetectorTechniqueMapping.technique_id, DetectorTechniqueMapping.control_type)
        .join(Detector, Detector.detector_key == DetectorTechniqueMapping.detector_key)
    ).all()
    pairs.extend((tid, ct) for tid, ct in det_rows)
    return pairs


def coverage_by_control_type(session: Session) -> dict[str, int]:
    """How many IN-SCOPE techniques are covered by each control type
    (PREV / DETECT / SCOPE / ...), with parent rollup.

    This is the headline message: where we BLOCK (PREV), where we only SEE
    (DETECT), where we LIMIT access (SCOPE). Agentic techniques come out as
    DETECT; endpoint artefacts as SCOPE/PREV.
    """
    techs = session.exec(select(Technique)).all()
    in_scope_ids = {t.technique_id for t in techs if t.in_scope}
    child_to_parent = {
        t.technique_id: t.parent_technique for t in techs if t.parent_technique
    }
    by_ct: dict[str, set[str]] = {}
    for tid, ct in _control_pairs(session):
        for target in (tid, child_to_parent.get(tid)):  # self + parent rollup
            if target and target in in_scope_ids:
                by_ct.setdefault(ct, set()).add(target)
    return {ct: len(ids) for ct, ids in by_ct.items()}


def coverage_detail(session: Session, technique_id: str) -> dict:
    """Everything the map needs for one technique: whether it's covered, BY WHAT
    (indicators + detectors), and with which control type(s). JSON-friendly."""
    tech = session.exec(
        select(Technique).where(Technique.technique_id == technique_id)
    ).first()
    if tech is None:
        return {"technique_id": technique_id, "found": False}

    # Indicators (active only) with their control type.
    indicators: list[dict] = []
    ind_rows = session.exec(
        select(ThreatIndicator, IndicatorTechniqueMapping.control_type)
        .join(
            IndicatorTechniqueMapping,
            IndicatorTechniqueMapping.indicator_id == ThreatIndicator.id,
        )
        .where(IndicatorTechniqueMapping.technique_id == technique_id)
        .where(ThreatIndicator.enabled == True)  # noqa: E712
        .where(ThreatIndicator.status == "active")
    ).all()
    for ind, control_type in ind_rows:
        indicators.append(
            {
                "id": ind.id,
                "indicator_type": ind.indicator_type,
                "value": ind.value,
                "control_type": control_type,
            }
        )

    # Detectors (registered only) with control type + relevance.
    detectors: list[dict] = []
    det_rows = session.exec(
        select(DetectorTechniqueMapping, Detector)
        .join(Detector, Detector.detector_key == DetectorTechniqueMapping.detector_key)
        .where(DetectorTechniqueMapping.technique_id == technique_id)
    ).all()
    for mapping, det in det_rows:
        detectors.append(
            {
                "detector_key": det.detector_key,
                "name": det.name,
                "control_type": mapping.control_type,
                "relevance": mapping.relevance,
            }
        )

    direct = _direct_covered_ids(session)
    effective = _effective_covered_ids(session)
    covered_by_children = sorted(
        t.technique_id
        for t in session.exec(
            select(Technique).where(Technique.parent_technique == technique_id)
        ).all()
        if t.technique_id in direct
    )
    control_types = sorted(
        {i["control_type"] for i in indicators} | {d["control_type"] for d in detectors}
    )

    return {
        "technique_id": technique_id,
        "found": True,
        "framework": tech.framework,
        "name": tech.name,
        "tactic": tech.tactic,
        "in_scope": tech.in_scope,
        "covered": technique_id in effective,
        "covered_directly": technique_id in direct,
        "covered_via_rollup": technique_id not in direct and technique_id in effective,
        "covered_by_children": covered_by_children,
        "control_types": control_types,
        "indicators": indicators,
        "detectors": detectors,
        "crosswalk": crosswalk_for(session, technique_id),
    }


# --------------------------------------------------------------------------- #
# Crosswalk (horizontal, cross-framework)                                      #
# --------------------------------------------------------------------------- #
def crosswalk_for(session: Session, technique_id: str) -> list[str]:
    """technique_ids ≈-linked to this one across frameworks (both directions)."""
    related: set[str] = set()
    for row in session.exec(
        select(TechniqueCrosswalk).where(
            or_(
                TechniqueCrosswalk.technique_id_a == technique_id,
                TechniqueCrosswalk.technique_id_b == technique_id,
            )
        )
    ).all():
        related.add(row.technique_id_a)
        related.add(row.technique_id_b)
    related.discard(technique_id)
    return sorted(related)


# --------------------------------------------------------------------------- #
# Existing both-direction joins + new-technique remap (ТЗ-06, unchanged)       #
# --------------------------------------------------------------------------- #
def indicators_for_technique(session: Session, technique_id: str) -> list[ThreatIndicator]:
    """All indicators mapped to a technique (both-directions query)."""
    return list(
        session.exec(
            select(ThreatIndicator)
            .join(
                IndicatorTechniqueMapping,
                IndicatorTechniqueMapping.indicator_id == ThreatIndicator.id,
            )
            .where(IndicatorTechniqueMapping.technique_id == technique_id)
        ).all()
    )


def techniques_for_indicator(session: Session, indicator_id: int) -> list[Technique]:
    """All techniques mapped to an indicator."""
    return list(
        session.exec(
            select(Technique)
            .join(
                IndicatorTechniqueMapping,
                IndicatorTechniqueMapping.technique_id == Technique.technique_id,
            )
            .where(IndicatorTechniqueMapping.indicator_id == indicator_id)
        ).all()
    )


def remap_indicators_to_technique(session: Session, technique_id: str) -> int:
    """Heuristically link existing indicators to a newly-arrived technique.

    Base heuristic (no LLM — that's a future ТЗ): indicators sharing the
    technique's tactic. Created links are tagged ``mapping_source="auto"`` with
    a low confidence so they are distinguishable from vetted seed links and can
    be reviewed before being trusted. Idempotent. Returns links created.
    """
    technique = session.exec(
        select(Technique).where(Technique.technique_id == technique_id)
    ).first()
    if technique is None:
        log.warning("remap: unknown technique %r", technique_id)
        return 0

    existing_pairs = {
        m.indicator_id
        for m in session.exec(
            select(IndicatorTechniqueMapping).where(
                IndicatorTechniqueMapping.technique_id == technique_id
            )
        ).all()
    }

    # Candidate indicators: same tactic, enabled+active, not already linked.
    candidates = session.exec(
        select(ThreatIndicator)
        .where(ThreatIndicator.tactic == technique.tactic)
        .where(ThreatIndicator.enabled == True)  # noqa: E712
        .where(ThreatIndicator.status == "active")
    ).all()

    created = 0
    for ind in candidates:
        if ind.id in existing_pairs:
            continue
        session.add(
            IndicatorTechniqueMapping(
                indicator_id=ind.id,
                technique_id=technique_id,
                mapping_source="auto",
                confidence=_AUTO_CONFIDENCE,
            )
        )
        created += 1

    if created:
        session.commit()
    return created
