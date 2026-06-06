"""Fleet-wide aggregation queries for SkillBaseline / AgentBaseline.

Used by the /admin/skills-inventory page. Single-table GROUP BY against
the denormalized parent_plugin + source_marketplace columns means no
join needed and no JSON-blob parsing.

See specs/2026-06-02-skills-agents-baseline-design.md.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from sqlalchemy import func
from sqlmodel import Session, select

from ccguard.server.db.models import AgentBaseline, SkillBaseline


@dataclass
class ArtifactSummary:
    """One row in the fleet artifacts table.

    `versions` holds {dir_hash_or_file_hash: machines_count}. When `len
    > 1` the artifact is divergent across the fleet — usually a strong
    signal of supply-chain compromise or local tampering. UI highlights
    these rows.
    """

    name: str
    origin: str
    parent_plugin: str | None
    source_marketplace: str | None
    machines_total: int = 0
    versions: dict[str, int] = field(default_factory=dict)

    @property
    def is_divergent(self) -> bool:
        return len(self.versions) > 1


def _aggregate(session: Session, table, hash_col_name: str) -> list[ArtifactSummary]:
    """Generic aggregator for Skill/AgentBaseline.

    Returns one ArtifactSummary per (name, origin, parent_plugin) slot,
    pre-sorted by machines_total descending so divergent / popular
    artifacts surface first.
    """
    hash_col = getattr(table, hash_col_name)
    rows = list(session.exec(
        select(
            table.name, table.origin, table.parent_plugin,
            table.source_marketplace, hash_col,
            func.count(func.distinct(table.machine_id)).label("machines"),
        ).where(table.status != "removed")
        .group_by(
            table.name, table.origin, table.parent_plugin,
            table.source_marketplace, hash_col,
        )
    ))

    by_slot: dict[tuple[str, str, str | None, str | None], ArtifactSummary] = {}
    for r in rows:
        # SQLAlchemy returns a Row — index by position to stay compatible
        # across SQLAlchemy 1.x / 2.x and SQLModel versions.
        name = r[0]
        origin = r[1]
        parent = r[2]
        marketplace = r[3]
        h = r[4]
        n = int(r[5])
        slot = (name, origin, parent, marketplace)
        summary = by_slot.get(slot)
        if summary is None:
            summary = ArtifactSummary(
                name=name, origin=origin,
                parent_plugin=parent, source_marketplace=marketplace,
            )
            by_slot[slot] = summary
        summary.versions[h] = summary.versions.get(h, 0) + n

    # machines_total — sum of all version-counts; divergent rows count
    # each machine only once even if it appears on multiple versions in
    # the (rare) case of cross-namespace duplication, because the
    # COUNT(DISTINCT machine_id) is per-version. That's the right shape
    # for "how many machines have this artifact in any form".
    for s in by_slot.values():
        s.machines_total = sum(s.versions.values())

    return sorted(
        by_slot.values(),
        key=lambda s: (not s.is_divergent, -s.machines_total, s.name),
    )


def aggregate_skills(session: Session) -> list[ArtifactSummary]:
    """All non-removed SkillBaseline rows aggregated to (name, origin,
    parent_plugin) slots with per-dir_hash version distribution."""
    return _aggregate(session, SkillBaseline, "dir_hash")


def aggregate_agents(session: Session) -> list[ArtifactSummary]:
    """All non-removed AgentBaseline rows aggregated to (name, origin,
    parent_plugin) slots with per-file_hash version distribution."""
    return _aggregate(session, AgentBaseline, "file_hash")


def machines_for_artifact(
    session: Session,
    table,
    *,
    name: str,
    origin: str,
    parent_plugin: str | None,
) -> list[tuple[str, str, str]]:
    """Drill-down: (machine_id, hash, status) for one artifact slot.

    Used by HTMX partial to expand a row in the fleet table.
    """
    hash_col = getattr(
        table, "dir_hash" if table is SkillBaseline else "file_hash"
    )
    rows = list(session.exec(
        select(table.machine_id, hash_col, table.status)
        .where(
            table.name == name,
            table.origin == origin,
            table.parent_plugin == (parent_plugin or None),
            table.status != "removed",
        )
    ))
    return [(str(r[0]), str(r[1]), str(r[2])) for r in rows]
