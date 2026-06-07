"""ATLAS coverage queries + new-technique remap (ТЗ-06).

Pure relational SQL (JOIN / LEFT JOIN / GROUP BY) over the 3-entity model —
ThreatIndicator ↔ IndicatorTechniqueMapping ↔ AtlasTechnique. No graph DB: the
relationships are fixed-depth many-to-many, which SQLite handles directly.

"Covered" = a technique with ≥1 ENABLED + ACTIVE indicator mapped to it. Pending
/ disabled indicators never count toward coverage — they are proposals, not
detection.
"""
from __future__ import annotations

import logging

from sqlmodel import Session, select

from ccguard.server.db.models import (
    AtlasTechnique,
    IndicatorTechniqueMapping,
    ThreatIndicator,
)

log = logging.getLogger(__name__)

# Auto-mappings created by the remap heuristic are deliberately low-confidence
# and tagged so they are distinguishable from vetted seed links (and reviewable).
_AUTO_CONFIDENCE = 0.3


def _directly_covered_ids(session: Session) -> set[str]:
    """technique_ids with at least one enabled+active indicator (the JOIN)."""
    rows = session.exec(
        select(IndicatorTechniqueMapping.technique_id)
        .join(ThreatIndicator, ThreatIndicator.id == IndicatorTechniqueMapping.indicator_id)
        .where(ThreatIndicator.enabled == True)  # noqa: E712
        .where(ThreatIndicator.status == "active")
    ).all()
    return set(rows)


def _effective_covered_ids(session: Session) -> set[str]:
    """Direct coverage PLUS rollup: a parent technique counts as covered when any
    of its sub-techniques is covered (covering T1552.001 covers T1552). Otherwise
    a fully-detected parent shows up as a gap purely because indicators attach to
    its sub-techniques — a false hole.
    """
    direct = _directly_covered_ids(session)
    if not direct:
        return set()
    covered = set(direct)
    for tech in session.exec(select(AtlasTechnique)).all():
        if tech.parent_technique and tech.technique_id in direct:
            covered.add(tech.parent_technique)
    return covered


def techniques_covered(session: Session) -> list[AtlasTechnique]:
    """Techniques we actually detect (≥1 active indicator, with parent rollup)."""
    covered = _effective_covered_ids(session)
    if not covered:
        return []
    return list(
        session.exec(
            select(AtlasTechnique).where(AtlasTechnique.technique_id.in_(covered))
        ).all()
    )


def techniques_uncovered(session: Session) -> list[AtlasTechnique]:
    """Coverage gaps: IN-SCOPE techniques with no (effective) coverage.

    Out-of-scope techniques (model-internal, an endpoint EDR can't cover) are
    excluded — they are not honest gaps, just noise on the map.
    """
    covered = _effective_covered_ids(session)
    stmt = select(AtlasTechnique).where(AtlasTechnique.in_scope == True)  # noqa: E712
    if covered:
        stmt = stmt.where(AtlasTechnique.technique_id.not_in(covered))
    return list(session.exec(stmt).all())


def coverage_by_tactic(session: Session) -> dict[str, dict[str, int]]:
    """Per-tactic summary {tactic: {covered, total}} over IN-SCOPE techniques,
    counting parent rollup as covered."""
    covered = _effective_covered_ids(session)
    out: dict[str, dict[str, int]] = {}
    for tech in session.exec(select(AtlasTechnique)).all():
        if not tech.in_scope:
            continue  # out-of-scope techniques don't count toward the map
        bucket = out.setdefault(tech.tactic, {"covered": 0, "total": 0})
        bucket["total"] += 1
        if tech.technique_id in covered:
            bucket["covered"] += 1
    return out


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


def techniques_for_indicator(session: Session, indicator_id: int) -> list[AtlasTechnique]:
    """All techniques mapped to an indicator."""
    return list(
        session.exec(
            select(AtlasTechnique)
            .join(
                IndicatorTechniqueMapping,
                IndicatorTechniqueMapping.technique_id == AtlasTechnique.technique_id,
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
        select(AtlasTechnique).where(AtlasTechnique.technique_id == technique_id)
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
