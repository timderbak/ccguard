"""CI guard: a curated corpus of FP-prone-but-BENIGN developer commands must
never trip the hard-deny tier. A false hard-block breaks real work, so this is
the safety net for the block-obvious-evil feature. Extend the fixture whenever a
real-world false positive surfaces."""
from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path

import pytest

from ccguard.agent.enforce import decide
from ccguard.agent.signals.cred_exfil import detect_cred_exfil
from ccguard.schemas import Policy, PolicyMeta
from ccguard.schemas.enforce import EnforceHookInput

_CMDS: list[str] = json.loads(
    (Path(__file__).resolve().parents[1] / "fixtures" / "benign_dev_corpus.json").read_text()
)["commands"]


def _enforce_policy() -> Policy:
    # enforce mode + minimal policy: the only thing that can deny is the hard tier
    return Policy(meta=PolicyMeta(revision=1, updated_at=datetime.now(UTC)), enforcement_mode="enforce")


def _bash(cmd: str) -> EnforceHookInput:
    return EnforceHookInput(hook_event_name="PreToolUse", tool_name="Bash", tool_input={"command": cmd})


@pytest.mark.parametrize("cmd", _CMDS)
def test_benign_command_not_hard_blocked(cmd: str):
    d = decide(_bash(cmd), _enforce_policy())
    assert not d.hard_deny, f"FALSE hard-block: {cmd!r} → {d.rule_id}: {d.reason}"


@pytest.mark.parametrize("cmd", _CMDS)
def test_benign_command_not_flagged_cred_exfil(cmd: str):
    assert not detect_cred_exfil(cmd), f"FALSE cred-exfil: {cmd!r}"
