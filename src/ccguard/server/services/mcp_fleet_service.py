"""Fleet-wide aggregation queries for MCPServerBaseline.

Used by the /admin/mcp-inventory page: "which MCP servers exist anywhere in
the org, WHERE DID EACH COME FROM, on how many machines, do they agree
byte-for-byte across the fleet, and how many instances has an admin actually
reviewed." Same spirit as skill_agent_fleet.py's ``_aggregate``, adapted to
MCPServerBaseline.

Provenance has two axes, both rolled up here: ``scope`` (managed = pushed by
the org / user = the developer installed it himself / project = committed in
the repo / project_local = local-only) and ``origin`` (plugin-shipped, with
plugin + marketplace, vs hand-declared). Unlike skills/agents — which live in
per-plugin directories — an MCP server is usually just a JSON entry in a
shared config, so the plugin link is only present when the server actually
ships inside an installed plugin's directory.

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

# Trust order for the provenance badge, most-sanctioned first. When one MCP
# name appears under several scopes across the fleet we surface the LEAST
# sanctioned one, because that's the instance an admin needs to look at: a
# server that is managed on 9 machines and hand-added on the 10th is exactly
# the interesting case, and showing "managed" there would hide it.
_SCOPE_TRUST_ORDER: tuple[str, ...] = ("managed", "project", "project_local", "user")


@dataclass
class McpFleetSummary:
    """One row in the fleet MCP inventory table.

    ``versions`` holds {definition_hash: machines_count} — ``None``-hash rows
    excluded (see module docstring). ``len(versions) > 1`` means the same MCP
    name launches DIFFERENT code on different machines. ``machines_pending``/
    ``machines_reviewed`` track the "проверено/не проверено" review state
    independent of divergence — a uniform, non-divergent MCP can still be
    entirely unreviewed.

    Provenance fields answer "откуда этот MCP взялся": ``scopes`` counts every
    scope the name was seen under across the fleet, ``origin``/``parent_plugin``/
    ``source_marketplace`` name the plugin when it shipped with one.
    """

    mcp_name: str
    transport: str
    machines_total: int = 0
    machines_reviewed: int = 0
    machines_pending: int = 0
    versions: dict[str, int] = field(default_factory=dict)
    scopes: dict[str, int] = field(default_factory=dict)
    origin: str = "local"
    parent_plugin: str | None = None
    source_marketplace: str | None = None

    @property
    def is_divergent(self) -> bool:
        return len(self.versions) > 1

    @property
    def fully_reviewed(self) -> bool:
        return self.machines_pending == 0

    @property
    def from_plugin(self) -> bool:
        return self.origin == "plugin" and bool(self.parent_plugin)

    @property
    def plugin_label(self) -> str | None:
        """``plugin@marketplace`` — same label shape the skills/agents fleet
        page uses, so provenance reads identically across artifact types."""
        if not self.from_plugin:
            return None
        return f"{self.parent_plugin}@{self.source_marketplace or 'unknown'}"

    @property
    def primary_scope(self) -> str | None:
        """Least-sanctioned scope seen across the fleet (see _SCOPE_TRUST_ORDER),
        or None when no agent reported provenance yet."""
        known = [s for s in self.scopes if s in _SCOPE_TRUST_ORDER]
        if not known:
            return None
        return max(known, key=_SCOPE_TRUST_ORDER.index)

    @property
    def scope_is_mixed(self) -> bool:
        """True when the same MCP name arrives via different scopes on different
        machines — e.g. centrally managed on most hosts but hand-added on one."""
        return len({s for s in self.scopes if s in _SCOPE_TRUST_ORDER}) > 1


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
            MCPServerBaseline.scope,
            MCPServerBaseline.origin,
            MCPServerBaseline.parent_plugin,
            MCPServerBaseline.source_marketplace,
            func.count(func.distinct(MCPServerBaseline.machine_id)).label("machines"),
        ).group_by(
            MCPServerBaseline.mcp_name,
            MCPServerBaseline.transport,
            MCPServerBaseline.definition_hash,
            MCPServerBaseline.status,
            MCPServerBaseline.scope,
            MCPServerBaseline.origin,
            MCPServerBaseline.parent_plugin,
            MCPServerBaseline.source_marketplace,
        )
    ))

    by_name: dict[str, McpFleetSummary] = {}
    for r in rows:
        name, transport, def_hash, status = r[0], r[1], r[2], r[3]
        scope, origin, parent_plugin, marketplace = r[4], r[5], r[6], r[7]
        n = int(r[8])
        summary = by_name.get(name)
        if summary is None:
            summary = McpFleetSummary(mcp_name=name, transport=transport)
            by_name[name] = summary
        else:
            summary.transport = transport
        if def_hash is not None:
            summary.versions[def_hash] = summary.versions.get(def_hash, 0) + n
        if scope:
            summary.scopes[scope] = summary.scopes.get(scope, 0) + n
        # Plugin attribution wins over the plain `local` default: if ANY machine
        # reports this MCP as plugin-shipped, that's the provenance worth naming
        # (a hand-copied duplicate elsewhere doesn't erase where it came from).
        if origin == "plugin" and parent_plugin:
            summary.origin = "plugin"
            summary.parent_plugin = parent_plugin
            summary.source_marketplace = marketplace
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
            "scope": r.scope,
            "origin": r.origin,
            "parent_plugin": r.parent_plugin,
            "source_marketplace": r.source_marketplace,
            "source_path": r.source_path,
        }
        for r in sorted(rows, key=lambda r: r.machine_id)
    ]
