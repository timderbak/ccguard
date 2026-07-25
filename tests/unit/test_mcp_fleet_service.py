"""Fleet-wide MCP aggregation: divergence detection + review-state rollup.

Единая база MCP по всему флоту — "какие проверены, какие не проверены" — is
the headline this module serves. Covers: grouping by name across machines,
definition_hash divergence (excluding None-hash v0.1 rows from the count so a
back-compat gap never manufactures a false divergence), and the reviewed/
pending rollup.
"""
from __future__ import annotations

from sqlmodel import Session

from ccguard.schemas import McpServerEntry
from ccguard.server.db.session import init_db, make_engine
from ccguard.server.services import mcp_baseline_service as baseline_svc
from ccguard.server.services import mcp_fleet_service as svc


def _engine():
    eng = make_engine("sqlite://")
    init_db(eng)
    return eng


def _mcp(
    name: str = "notion",
    command: str | None = "npx",
    args: list[str] | None = None,
    description: str | None = "a tool",
    tools_hash: str | None = None,
) -> McpServerEntry:
    """Build an McpServerEntry with auto-computed hashes (mirrors the agent;
    same helper shape as test_mcp_baseline_service.py's ``_mcp``)."""
    from ccguard.agent.scan.mcp import _definition_text, _hash_text

    args = args or ["-y", "@notion/mcp"]
    return McpServerEntry(
        name=name,
        transport="stdio",
        command=command,
        args=args,
        url=None,
        env_keys=[],
        source="/test/.claude.json",
        description=description,
        description_hash=_hash_text(description),
        definition_hash=_hash_text(_definition_text(command, args, None)),
        tools_hash=tools_hash,
    )


def test_empty_fleet_returns_empty_list():
    engine = _engine()
    with Session(engine) as s:
        assert svc.aggregate_mcp_servers(s) == []


def test_single_machine_single_mcp():
    engine = _engine()
    with Session(engine) as s:
        baseline_svc.update_and_detect(s, "m1", [_mcp("notion")])
        s.commit()
        rows = svc.aggregate_mcp_servers(s)
    assert len(rows) == 1
    assert rows[0].mcp_name == "notion"
    assert rows[0].machines_total == 1
    assert rows[0].machines_pending == 1
    assert rows[0].machines_reviewed == 0
    assert not rows[0].is_divergent


def test_same_mcp_same_hash_across_machines_not_divergent():
    engine = _engine()
    with Session(engine) as s:
        baseline_svc.update_and_detect(s, "m1", [_mcp("notion")])
        baseline_svc.update_and_detect(s, "m2", [_mcp("notion")])
        baseline_svc.update_and_detect(s, "m3", [_mcp("notion")])
        s.commit()
        rows = svc.aggregate_mcp_servers(s)
    assert len(rows) == 1
    assert rows[0].machines_total == 3
    assert not rows[0].is_divergent
    assert len(rows[0].versions) == 1


def test_same_name_different_command_is_divergent():
    # Same MCP name, different launch command -> different definition_hash ->
    # the exact "supply-chain compromise on a subset of hosts" signal.
    engine = _engine()
    with Session(engine) as s:
        baseline_svc.update_and_detect(s, "m1", [_mcp("notion", command="npx")])
        baseline_svc.update_and_detect(s, "m2", [_mcp("notion", command="/tmp/evil-npx")])
        s.commit()
        rows = svc.aggregate_mcp_servers(s)
    assert len(rows) == 1
    assert rows[0].is_divergent
    assert len(rows[0].versions) == 2
    assert rows[0].machines_total == 2


def test_none_definition_hash_excluded_from_divergence():
    # A v0.1 agent row with definition_hash=None must NOT manufacture a false
    # "divergent" flag just because hash data is missing.
    engine = _engine()
    with Session(engine) as s:
        baseline_svc.update_and_detect(s, "m1", [_mcp("notion")])
        s.commit()
        from ccguard.server.db.models import MCPServerBaseline

        old_agent_row = MCPServerBaseline(
            machine_id="m2", mcp_name="notion", transport="stdio",
            definition_hash=None, status="pending",
        )
        s.add(old_agent_row)
        s.commit()
        rows = svc.aggregate_mcp_servers(s)
    assert len(rows) == 1
    assert not rows[0].is_divergent  # only 1 real hash value counted
    assert rows[0].machines_total == 2  # but still counted toward the total


def test_divergent_sorts_before_non_divergent():
    engine = _engine()
    with Session(engine) as s:
        baseline_svc.update_and_detect(s, "m1", [_mcp("stable-mcp")])
        baseline_svc.update_and_detect(s, "m1", [_mcp("weird-mcp", command="a")])
        baseline_svc.update_and_detect(s, "m2", [_mcp("weird-mcp", command="b")])
        s.commit()
        rows = svc.aggregate_mcp_servers(s)
    assert rows[0].mcp_name == "weird-mcp"
    assert rows[0].is_divergent
    assert rows[1].mcp_name == "stable-mcp"


def test_reviewed_pending_rollup():
    engine = _engine()
    with Session(engine) as s:
        baseline_svc.update_and_detect(s, "m1", [_mcp("notion")])
        baseline_svc.update_and_detect(s, "m2", [_mcp("notion")])
        baseline_svc.update_and_detect(s, "m3", [_mcp("notion")])
        s.commit()
        baseline_svc.mark_reviewed(s, "m1", "notion", reviewed_by="alice")
        baseline_svc.mark_reviewed(s, "m2", "notion", reviewed_by="alice")
        rows = svc.aggregate_mcp_servers(s)
    assert rows[0].machines_reviewed == 2
    assert rows[0].machines_pending == 1
    assert not rows[0].fully_reviewed


def test_fully_reviewed_true_when_no_pending():
    engine = _engine()
    with Session(engine) as s:
        baseline_svc.update_and_detect(s, "m1", [_mcp("notion")])
        s.commit()
        baseline_svc.mark_reviewed(s, "m1", "notion", reviewed_by="alice")
        rows = svc.aggregate_mcp_servers(s)
    assert rows[0].fully_reviewed


def test_two_distinct_mcp_names_two_rows():
    engine = _engine()
    with Session(engine) as s:
        baseline_svc.update_and_detect(s, "m1", [_mcp("notion")])
        baseline_svc.update_and_detect(s, "m1", [_mcp("airtable")])
        s.commit()
        rows = svc.aggregate_mcp_servers(s)
    assert {r.mcp_name for r in rows} == {"notion", "airtable"}


def test_machines_for_mcp_drill_down():
    engine = _engine()
    with Session(engine) as s:
        baseline_svc.update_and_detect(s, "m2", [_mcp("notion")])
        baseline_svc.update_and_detect(s, "m1", [_mcp("notion")])
        s.commit()
        baseline_svc.mark_reviewed(s, "m1", "notion", reviewed_by="alice")
        drill = svc.machines_for_mcp(s, "notion")
    assert [d["machine_id"] for d in drill] == ["m1", "m2"]  # sorted
    assert drill[0]["status"] == "active"
    assert drill[0]["accepted_by"] == "alice"
    assert drill[1]["status"] == "pending"
    assert drill[1]["accepted_by"] is None


def test_machines_for_mcp_unknown_name_returns_empty():
    engine = _engine()
    with Session(engine) as s:
        assert svc.machines_for_mcp(s, "ghost") == []
