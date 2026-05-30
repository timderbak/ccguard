"""Stage 5b: agent's decide() honors policy.enforcement_mode.

In ``observe`` mode, a deny decision is flipped to allow with
``would_have_denied=True`` so the audit trail captures intent without
blocking the user's tool call.
"""
from __future__ import annotations

import yaml

from ccguard.agent.enforce import decide
from ccguard.schemas import Policy
from ccguard.schemas.enforce import EnforceHookInput


def _policy(mode: str | None = None, deny_curl: bool = True) -> Policy:
    doc = {
        "meta": {"revision": 1, "updated_at": "2026-05-30T00:00:00Z"},
        "commands": {
            "severity": "block",
            "denylist_patterns": [r"\bcurl\b"] if deny_curl else [],
        },
    }
    if mode is not None:
        doc["enforcement_mode"] = mode
    return Policy.model_validate(yaml.safe_load(yaml.safe_dump(doc)))


def _hook(cmd: str) -> EnforceHookInput:
    return EnforceHookInput(
        hook_event_name="PreToolUse", tool_name="Bash", tool_input={"command": cmd}
    )


def test_schema_default_is_observe_so_deny_flips_to_allow():
    """No enforcement_mode field → schema default is observe (closes the
    'remove all blocking' user ask). Deny → allow with observe-mode annotation."""
    decision = decide(_hook("curl https://evil.com"), _policy())
    assert decision.permission == "allow"
    assert "observe" in decision.reason.lower()


def test_explicit_enforce_mode_blocks_denied_command():
    decision = decide(_hook("curl https://evil.com"), _policy(mode="enforce"))
    assert decision.permission == "deny"


def test_observe_mode_flips_deny_to_allow():
    decision = decide(_hook("curl https://evil.com"), _policy(mode="observe"))
    assert decision.permission == "allow"
    # The reason field should signal observe-mode override so the audit
    # event downstream can be filtered.
    assert "observe" in decision.reason.lower()


def test_observe_mode_preserves_rule_id():
    """observed_rule_id stays in reason so SOC can see WHAT would have denied."""
    decision = decide(_hook("curl https://evil.com"), _policy(mode="observe"))
    assert decision.rule_id is not None


def test_observe_mode_does_not_change_already_allow():
    """An allowed command stays allowed regardless of mode."""
    decision = decide(_hook("ls"), _policy(mode="observe"))
    assert decision.permission == "allow"


def test_invalid_mode_rejected_at_schema_validation():
    """Pydantic Literal rejects unknown mode strings at policy load time —
    that's the safety mechanism. Caller never sees ``policy.enforcement_mode``
    set to an unexpected value."""
    import pytest as _pt
    from pydantic import ValidationError as _VE
    with _pt.raises(_VE):
        _policy(mode="bogus")
