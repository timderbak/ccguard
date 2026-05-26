"""Backward-compat proof for v0.1 agents reading an extended v0.2 policy.

Locked decision D-1 (see 04-CONTEXT.md): schema_version stays at 1 and the v0.1
agent's Pydantic model is required to use ``extra='ignore'`` so it survives
extended-policy bodies that carry the 4 new mandatory sections plus arbitrary
future fields.

This test DELIBERATELY does NOT import any production v0.1 surface. The whole
point is to simulate an OLD agent's parser as it would actually have shipped
— so the simulated v0.1 model is defined inline. If a future refactor breaks
the contract, the production Policy model can no longer claim D-1 compliance
and this test will catch it before agents in the field crash on update.
"""

from __future__ import annotations

from datetime import UTC, datetime

import pytest
from pydantic import BaseModel, ConfigDict, ValidationError

from ccguard.schemas import Policy


# ---------------------------------------------------------------------------
# Inline simulated v0.1 model — minimal subset of the production Policy that
# pre-dates the Phase 4 additions. NO required_*, NO managed_claude_md_blocks.
# ---------------------------------------------------------------------------


class _V01PolicyMeta(BaseModel):
    revision: int
    name: str = "default"
    updated_at: datetime
    # NOTE: v0.1 did NOT carry schema_version — kept absent on purpose.


class _V01Policy(BaseModel):
    """Simulated v0.1 Policy parser. Must accept extended v0.2 bodies."""

    model_config = ConfigDict(extra="ignore", str_strip_whitespace=True)

    meta: _V01PolicyMeta
    block_fail_mode: str = "open"


# ---------------------------------------------------------------------------
# Test corpus
# ---------------------------------------------------------------------------


def _extended_policy_dict(**overrides) -> dict:
    base = {
        "meta": {
            "revision": 12,
            "name": "extended",
            "updated_at": datetime.now(UTC).isoformat(),
        },
        "block_fail_mode": "open",
        # The 4 new sections — must be IGNORED by a v0.1 parser.
        "required_skills": [
            {
                "name": "sec",
                "frontmatter_type": "skill",
                "content": "---\nname: sec\n---\nbody",
            }
        ],
        "required_agents": [{"name": "rev", "content": "body"}],
        "required_mcp_servers": [
            {
                "name": "stripe",
                "command": "/usr/bin/x",
                "args": ["-y"],
                "env": {},
            }
        ],
        "managed_claude_md_blocks": [
            {"id": "security-rules", "description": "", "content": "X"}
        ],
        # And a hypothetical unknown future field — also ignored.
        "future_unknown_field": {"nested": [1, 2, 3]},
    }
    base.update(overrides)
    return base


# ---- 1. The core D-1 promise ------------------------------------------------


def test_v01_agent_parses_extended_policy_and_ignores_new_fields() -> None:
    payload = _extended_policy_dict()
    p = _V01Policy.model_validate(payload)
    # v0.1 fields preserved
    assert p.meta.revision == 12
    assert p.block_fail_mode == "open"
    # New fields are absent on the parsed v0.1 object — extra='ignore'
    for new_field in (
        "required_skills",
        "required_agents",
        "required_mcp_servers",
        "managed_claude_md_blocks",
        "future_unknown_field",
    ):
        assert not hasattr(p, new_field), (
            f"v0.1 parser leaked {new_field!r} into the object — extra='ignore' regression"
        )


# ---- 2. schema_version variants ---------------------------------------------


def test_v01_agent_tolerates_schema_version_1_on_meta() -> None:
    """Production v0.2 stamps schema_version=1 on meta. v0.1 agents accept it."""
    payload = _extended_policy_dict()
    payload["meta"]["schema_version"] = 1  # production stamp
    p = _V01Policy.model_validate(payload)
    assert p.meta.revision == 12
    # And of course schema_version did not leak onto the v0.1 meta model
    assert not hasattr(p.meta, "schema_version")


def test_v01_agent_tolerates_unknown_schema_version_999() -> None:
    """A hypothetical schema_version bump does NOT crash a v0.1 agent."""
    payload = _extended_policy_dict()
    payload["meta"]["schema_version"] = 999
    p = _V01Policy.model_validate(payload)
    assert p.meta.revision == 12


def test_v01_agent_tolerates_top_level_schema_version() -> None:
    """If a future server places schema_version at the top level instead of
    meta, the v0.1 parser must still survive."""
    payload = _extended_policy_dict()
    payload["schema_version"] = 2
    p = _V01Policy.model_validate(payload)
    assert p.meta.revision == 12


# ---- 3. Strictness in the v0.2 model (additivity proof) ---------------------


def test_v02_policy_validates_the_same_extended_body_strictly() -> None:
    """The v0.2 Policy MUST validate the same extended dict — the new fields
    are additive, not breaking. This is the additivity half of D-1."""
    payload = _extended_policy_dict()
    p2 = Policy.model_validate(payload)
    # v0.2 surfaces the new sections
    assert len(p2.required_skills) == 1
    assert p2.required_skills[0].name == "sec"
    assert len(p2.required_agents) == 1
    assert p2.required_agents[0].name == "rev"
    assert len(p2.required_mcp_servers) == 1
    assert p2.required_mcp_servers[0].name == "stripe"
    assert len(p2.managed_claude_md_blocks) == 1
    assert p2.managed_claude_md_blocks[0].id == "security-rules"


def test_v02_policy_ignores_unknown_top_level_fields() -> None:
    """D-1 also requires the v0.2 Policy itself to use extra='ignore' so the
    NEXT agent generation survives a v0.3 server. Belt-and-suspenders proof."""
    payload = _extended_policy_dict()
    payload["v03_unknown_section"] = {"x": "y"}
    p2 = Policy.model_validate(payload)
    assert not hasattr(p2, "v03_unknown_section")


def test_v02_policy_rejects_malformed_required_section() -> None:
    """The v0.2 model REJECTS structurally wrong required_* fields — proves
    the new validation is strict (not 'ignore everything new')."""
    payload = _extended_policy_dict()
    payload["required_mcp_servers"] = 42  # not a list
    with pytest.raises(ValidationError):
        Policy.model_validate(payload)


def test_v01_agent_ignores_malformed_required_section() -> None:
    """The same malformed body that v0.2 rejects, v0.1 accepts (because it
    ignores the field entirely)."""
    payload = _extended_policy_dict()
    payload["required_mcp_servers"] = 42  # not a list — but ignored at v0.1
    p = _V01Policy.model_validate(payload)
    assert p.meta.revision == 12


# ---- 4. Empty no-op compatibility ------------------------------------------


def test_v01_agent_parses_pure_v01_body_unchanged() -> None:
    """Sanity: a body with no new sections is still parseable by v0.1."""
    pure_v01 = {
        "meta": {
            "revision": 1,
            "name": "pure",
            "updated_at": datetime.now(UTC).isoformat(),
        },
        "block_fail_mode": "open",
    }
    p = _V01Policy.model_validate(pure_v01)
    assert p.meta.revision == 1
