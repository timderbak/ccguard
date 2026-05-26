"""Unit tests for Policy mandatory-sections extension (Plan 04-01, Task 1).

Covers:
- 4 new optional sections default to empty lists
- Round-trip of each new section (required_mcp_servers, required_skills,
  required_agents, managed_claude_md_blocks)
- ManagedClaudeMdBlock.id kebab-case validator
- Backward-compat: ``extra='ignore'`` lets a v0.1 client read a future-extended
  policy without raising; v0.1 fixture (no new sections) still validates and
  emits empty lists.
"""
from __future__ import annotations

from datetime import UTC, datetime

import pytest
from pydantic import ValidationError

from ccguard.schemas.policy import (
    ManagedClaudeMdBlock,
    Policy,
    PolicyMeta,
    RequiredAgent,
    RequiredMCPServer,
    RequiredSkill,
)


def _meta() -> PolicyMeta:
    return PolicyMeta(revision=1, updated_at=datetime.now(UTC))


def _base_policy_dict() -> dict:
    return {
        "meta": {
            "schema_version": 1,
            "revision": 1,
            "name": "default",
            "updated_at": datetime.now(UTC).isoformat(),
        }
    }


def test_policy_defaults_empty_lists_for_new_sections() -> None:
    p = Policy.model_validate(_base_policy_dict())
    assert p.required_mcp_servers == []
    assert p.required_skills == []
    assert p.required_agents == []
    assert p.managed_claude_md_blocks == []


def test_required_mcp_server_roundtrip() -> None:
    data = _base_policy_dict()
    data["required_mcp_servers"] = [
        {"name": "x", "command": "/bin/x", "args": ["-y"], "env": {"K": "v"}}
    ]
    p = Policy.model_validate(data)
    assert len(p.required_mcp_servers) == 1
    mcp = p.required_mcp_servers[0]
    assert isinstance(mcp, RequiredMCPServer)
    assert mcp.name == "x"
    assert mcp.command == "/bin/x"
    assert mcp.args == ["-y"]
    assert mcp.env == {"K": "v"}
    # Round-trip
    restored = Policy.model_validate(p.model_dump())
    assert restored.required_mcp_servers[0].name == "x"


def test_required_skill_roundtrip_full_content() -> None:
    content = "---\nname: sec\n---\nbody"
    data = _base_policy_dict()
    data["required_skills"] = [
        {"name": "sec", "frontmatter_type": "skill", "content": content}
    ]
    p = Policy.model_validate(data)
    skill = p.required_skills[0]
    assert isinstance(skill, RequiredSkill)
    assert skill.name == "sec"
    assert skill.frontmatter_type == "skill"
    assert skill.content == content


def test_required_agent_roundtrip() -> None:
    content = "---\nname: reviewer\n---\n..."
    data = _base_policy_dict()
    data["required_agents"] = [{"name": "reviewer", "content": content}]
    p = Policy.model_validate(data)
    agent = p.required_agents[0]
    assert isinstance(agent, RequiredAgent)
    assert agent.name == "reviewer"
    assert agent.content == content


def test_managed_claude_md_block_roundtrip() -> None:
    data = _base_policy_dict()
    data["managed_claude_md_blocks"] = [
        {"id": "security-rules", "description": "d", "content": "X"}
    ]
    p = Policy.model_validate(data)
    blk = p.managed_claude_md_blocks[0]
    assert isinstance(blk, ManagedClaudeMdBlock)
    assert blk.id == "security-rules"
    assert blk.description == "d"
    assert blk.content == "X"


def test_managed_claude_md_block_id_kebab_case_required() -> None:
    # Underscore is rejected
    with pytest.raises(ValidationError):
        ManagedClaudeMdBlock(id="Security_Rules", description="", content="x")
    # Uppercase is rejected
    with pytest.raises(ValidationError):
        ManagedClaudeMdBlock(id="Foo", description="", content="x")
    # Leading/trailing dash rejected
    with pytest.raises(ValidationError):
        ManagedClaudeMdBlock(id="-foo", description="", content="x")
    with pytest.raises(ValidationError):
        ManagedClaudeMdBlock(id="foo-", description="", content="x")
    # Double dash rejected
    with pytest.raises(ValidationError):
        ManagedClaudeMdBlock(id="foo--bar", description="", content="x")
    # Single-segment OK
    assert ManagedClaudeMdBlock(id="foo", description="", content="x").id == "foo"
    # Multi-segment kebab OK
    assert (
        ManagedClaudeMdBlock(id="abc-def-123", description="", content="x").id
        == "abc-def-123"
    )


def test_policy_backward_compat_extra_ignored() -> None:
    """A v0.1 client receiving a future-extended policy must not raise.

    Proves ``model_config['extra'] == 'ignore'`` on the Policy model.
    """
    data = _base_policy_dict()
    data["unknown_future_section"] = [1, 2, 3]
    data["required_mcp_servers"] = []
    p = Policy.model_validate(data)
    # Unknown key is silently dropped.
    assert not hasattr(p, "unknown_future_section")
    dumped = p.model_dump()
    assert "unknown_future_section" not in dumped


def test_policy_v01_fixture_still_validates_and_dumps_empty_lists() -> None:
    """An existing v0.1 policy (no new sections) loads and emits empty lists."""
    p = Policy.model_validate(_base_policy_dict())
    dumped = p.model_dump()
    assert dumped["required_mcp_servers"] == []
    assert dumped["required_skills"] == []
    assert dumped["required_agents"] == []
    assert dumped["managed_claude_md_blocks"] == []


def test_policy_schema_version_unchanged() -> None:
    """schema_version stays at 1 — additive change per D-1."""
    p = Policy.model_validate(_base_policy_dict())
    assert p.meta.schema_version == 1
