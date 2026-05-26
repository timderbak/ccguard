"""Backward-compat proof for v0.1 agents consuming a v0.2 PI-extended policy.

Locked decision D-1 (05-CONTEXT §Backward Compat): schema_version stays at 1
and the new ``prompt_injection`` section is additive. A pinned v0.1 agent
schema (no PI awareness) must continue to parse policies emitted by a v0.2
server with the new section — pydantic ``extra='ignore'`` is the contract.

This module does NOT import the production PI schema from the v0.1
simulation block: the whole point is to exercise the parser shape a v0.1
agent would actually have shipped. The production ``Policy`` model is
imported separately to verify the symmetric path (v0.2 reads v0.1 policy
without the section and gets sane defaults).
"""

from __future__ import annotations

from datetime import UTC, datetime

import yaml
from pydantic import BaseModel, ConfigDict

from ccguard.schemas import Policy


# ---------------------------------------------------------------------------
# Inline simulated v0.1 Policy parser (no PI fields).
# ---------------------------------------------------------------------------


class _V01PolicyMeta(BaseModel):
    revision: int
    name: str = "default"
    updated_at: datetime


class _V01Policy(BaseModel):
    """v0.1 Policy parser — pre-dates Phase 5 PI section."""

    model_config = ConfigDict(extra="ignore", str_strip_whitespace=True)

    meta: _V01PolicyMeta
    block_fail_mode: str = "open"


def _v02_policy_yaml_with_pi() -> str:
    """Produce a YAML body shaped like a v0.2 server-published policy that
    includes the new prompt_injection section."""
    doc = {
        "meta": {
            "schema_version": 1,
            "revision": 42,
            "name": "v0.2-extended",
            "updated_at": datetime.now(UTC).isoformat(),
        },
        "block_fail_mode": "open",
        "prompt_injection": {
            "enabled": True,
            "severity": "block",
            "regex_patterns": ["custom_attack"],
            "allowlist_patterns": ["security_workflow"],
            "llama_guard": {
                "enabled": False,
                "endpoint": "http://localhost:11434",
                "model": "llama-guard3:8b",
                "timeout_ms": 150,
            },
        },
    }
    return yaml.safe_dump(doc, sort_keys=False)


# ---------- bc-1: v0.1 schema ignores v0.2 prompt_injection ---------------


def test_v01_agent_parses_v02_policy_ignoring_prompt_injection() -> None:
    """v0.1 parser must accept a v0.2 policy body WITHOUT raising on the
    unknown ``prompt_injection`` top-level field. ``extra='ignore'`` on the
    v0.1 model silently drops the section."""
    yaml_text = _v02_policy_yaml_with_pi()
    data = yaml.safe_load(yaml_text)
    parsed = _V01Policy.model_validate(data)
    assert parsed.meta.revision == 42
    assert parsed.block_fail_mode == "open"
    # The v0.1 model does NOT expose prompt_injection — verify the attr is
    # not present on the instance (extra='ignore' drops it, not preserves it).
    assert not hasattr(parsed, "prompt_injection")


# ---------- bc-2: v0.2 schema fills defaults when PI section absent -------


def test_v02_parses_legacy_policy_without_prompt_injection_section() -> None:
    """A legacy v0.1 policy YAML (no prompt_injection key) must parse under
    the v0.2 Policy with sane defaults: enabled=True, severity='warn'."""
    legacy_doc = {
        "meta": {
            "schema_version": 1,
            "revision": 1,
            "name": "legacy",
            "updated_at": datetime.now(UTC).isoformat(),
        },
        "block_fail_mode": "open",
    }
    policy = Policy.model_validate(legacy_doc)
    assert policy.prompt_injection.enabled is True
    assert policy.prompt_injection.severity == "warn"
    assert policy.prompt_injection.regex_patterns == []
    assert policy.prompt_injection.allowlist_patterns == []
    assert policy.prompt_injection.llama_guard.enabled is False


# ---------- bc-3: v0.2 ignores forward-compat fields inside PI section ----


def test_v02_ignores_future_prompt_injection_subfields() -> None:
    """Per Phase 5 D-1 (additive subfields), a hypothetical v0.3 server may
    add new keys under ``prompt_injection`` (e.g. per-category overrides).
    The v0.2 ``PromptInjectionConfig`` model_config sets ``extra='ignore'``
    so the unknown fields are silently dropped instead of raising."""
    doc = {
        "meta": {
            "schema_version": 1,
            "revision": 7,
            "name": "future",
            "updated_at": datetime.now(UTC).isoformat(),
        },
        "block_fail_mode": "open",
        "prompt_injection": {
            "enabled": True,
            "severity": "warn",
            "future_field_v0_3": "ml_classifier_threshold",
            "category_overrides": {"jailbreak_template": "block"},
            "llama_guard": {
                "enabled": False,
                "new_lg_field": "speculative",
            },
        },
    }
    policy = Policy.model_validate(doc)
    assert policy.prompt_injection.enabled is True
    assert policy.prompt_injection.severity == "warn"
    # Future subfields are dropped, not preserved as attrs.
    assert not hasattr(policy.prompt_injection, "future_field_v0_3")
    assert not hasattr(policy.prompt_injection, "category_overrides")
    assert not hasattr(policy.prompt_injection.llama_guard, "new_lg_field")


# ---------- bc-4: v0.2 Policy extra='ignore' top-level survives v0.3 ----


def test_v02_policy_ignores_future_top_level_sections() -> None:
    """Top-level ``Policy.model_config.extra='ignore'`` — confirms the same
    forward-compat guarantee at the outer schema layer (D-1 continuity)."""
    doc = {
        "meta": {
            "schema_version": 1,
            "revision": 99,
            "name": "future-top",
            "updated_at": datetime.now(UTC).isoformat(),
        },
        "block_fail_mode": "open",
        # Hypothetical v0.3 top-level section
        "ml_anomaly_detection": {"enabled": True, "model": "iforest"},
    }
    policy = Policy.model_validate(doc)
    assert policy.meta.revision == 99
    assert not hasattr(policy, "ml_anomaly_detection")
