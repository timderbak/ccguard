"""Fleet-wide aggregation queries for MCPServerBaseline.

Used by the /admin/mcp-inventory page: "which MCP servers exist anywhere in
the org, on how many machines, do they agree byte-for-byte across the fleet,
and how many instances has an admin actually reviewed." Same spirit as
skill_agent_fleet.py's ``_aggregate``, adapted to MCPServerBaseline's simpler
schema — no marketplace/plugin grouping, since MCP servers are named by each
developer's own settings.json, not distributed via a shared marketplace.

Divergence is judged on ``definition_hash`` — the launch command/args/url,
i.e. WHAT ACTUALLY RUNS — mirroring dir_hash/file_hash's role for skills/
agents (the content hash, not the human-facing description). A name with
multiple definition_hash values across the fleet is either a legitimate
per-environment variant or a supply-chain compromise on a subset of hosts;
either way it deserves a human look, so it always sorts first.

Rows with ``definition_hash IS NULL`` (v0.1 agents that don't send hashes —
see :class:`MCPServerBaseline`'s docstring) are excluded from the divergence
count itself: missing data is not evidence of a different version, and
counting it as one would manufacture a false "divergent" flag purely from an
unupgraded agent. They still count toward ``machines_total``/reviewed/pending.
"""
from __future__ import annotations

from dataclasses import dataclass, field

from sqlalchemy import func
from sqlmodel import Session, select

from ccguard.server.db.models import MCPServerBaseline


@dataclass
class McpFleetSummary:
    """One row in the fleet MCP inventory table.

    ``versions`` holds {definition_hash: machines_count} — ``None``-hash rows
    excluded (see module docstring). ``len(versions) > 1`` means the same MCP
    name launches DIFFERENT code on different machines. ``machines_pending``/
    ``machines_reviewed`` track the "проверено/не проверено" review state
    independent of divergence — a uniform, non-divergent MCP can still be
    entirely unreviewed.
    """

    mcp_name: str
    transport: str
    machines_total: int = 0
    machines_reviewed: int = 0
    machines_pending: int = 0
    versions: dict[str, int] = field(default_factory=dict)

    @property
    def is_divergent(self) -> bool:
        return len(self.versions) > 1

    @property
    def fully_reviewed(self) -> bool:
        return self.machines_pending == 0


def aggregate_mcp_servers(session: Session) -> list[McpFleetSummary]:
    """Every distinct MCP server name across the whole fleet, aggregated.

    Sorted divergent-first, then by machine count descending, then name — the
    rows most worth an admin's attention surface first.
    """
    rows = list(session.exec(
        select(
            MCPServerBaseline.mcp_name,
            MCPServerBaseline.transport,
            MCPServerBaseline.definition_hash,
            MCPServerBaseline.status,
            func.count(func.distinct(MCPServerBaseline.machine_id)).label("machines"),
        ).group_by(
            MCPServerBaseline.mcp_name,
            MCPServerBaseline.transport,
            MCPServerBaseline.definition_hash,
            MCPServerBaseline.status,
        )
    ))

    by_name: dict[str, McpFleetSummary] = {}
    for r in rows:
        name, transport, def_hash, status, n = r[0], r[1], r[2], r[3], int(r[4])
        summary = by_name.get(name)
        if summary is None:
            summary = McpFleetSummary(mcp_name=name, transport=transport)
            by_name[name] = summary
        else:
            summary.transport = transport
        if def_hash is not None:
            summary.versions[def_hash] = summary.versions.get(def_hash, 0) + n
        if status == "active":
            summary.machines_reviewed += n
        else:
            summary.machines_pending += n

    for s in by_name.values():
        s.machines_total = s.machines_reviewed + s.machines_pending

    return sorted(
        by_name.values(),
        key=lambda s: (not s.is_divergent, -s.machines_total, s.mcp_name),
    )


def machines_for_mcp(session: Session, mcp_name: str) -> list[dict[str, object]]:
    """Drill-down: one row per machine running ``mcp_name`` — hashes, review
    state, who/when reviewed. Used by the HTMX partial expanding a fleet-
    inventory row. Sorted by machine_id for a stable render.
    """
    rows = list(
        session.exec(
            select(MCPServerBaseline).where(MCPServerBaseline.mcp_name == mcp_name)
        )
    )
    return [
        {
            "machine_id": r.machine_id,
            "transport": r.transport,
            "definition_hash": r.definition_hash,
            "description_hash": r.description_hash,
            "tools_hash": r.tools_hash,
            "status": r.status,
            "accepted_by": r.accepted_by,
            "accepted_at": r.accepted_at,
            "last_seen_at": r.last_seen_at,
        }
        for r in sorted(rows, key=lambda r: r.machine_id)
    ]
