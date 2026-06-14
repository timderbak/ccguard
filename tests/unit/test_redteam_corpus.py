"""CI guard for red-team round-1: bypass attempts a multi-agent red-team devised
by reading the real detector code, which the deterministic eval confirmed EVADED
detection — now closed. Each case must fire its target_signal through the REAL
extractor. Prevents the closed evasions from silently regressing.

Methodology: ccguard-redteam-round1 workflow (8 attack classes read catalog.py /
normalize.py / enforce.py) → deterministic eval against extract_signals/decide →
fix the signal-missed gaps → lock here. Extend on future rounds."""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from ccguard.agent.signals.extractor import extract_signals

_CASES = json.loads(
    (Path(__file__).resolve().parents[1] / "fixtures" / "redteam_corpus.json").read_text()
)["cases"]


@pytest.mark.parametrize("case", _CASES, ids=[c["target_signal"] + ":" + c["command"][:40] for c in _CASES])
def test_redteam_bypass_now_caught(case: dict) -> None:
    fired = set(extract_signals("Bash", {"command": case["command"]}))
    assert case["target_signal"] in fired, (
        f"RED-TEAM REGRESSION: {case['intent']!r}\n  cmd: {case['command']!r}\n"
        f"  expected {case['target_signal']} — fired {sorted(fired) or '(none)'}"
    )


_REVSHELL = [c for c in _CASES if c["target_signal"] == "c2.reverse_shell"]


@pytest.mark.parametrize("case", _REVSHELL, ids=[c["command"][:40] for c in _REVSHELL])
def test_redteam_reverse_shell_also_hard_blocks(case: dict) -> None:
    # reverse shells are never legitimate → the enforce hard-deny rule (mirror of
    # the signal) must block them out of the box, even in observe mode.
    from datetime import UTC, datetime

    from ccguard.agent.enforce import decide
    from ccguard.schemas import Policy, PolicyMeta
    from ccguard.schemas.enforce import EnforceHookInput

    pol = Policy(meta=PolicyMeta(revision=1, updated_at=datetime.now(UTC)), enforcement_mode="observe")
    d = decide(
        EnforceHookInput(hook_event_name="PreToolUse", tool_name="Bash", tool_input={"command": case["command"]}),
        pol,
    )
    assert d.permission == "deny" and d.hard_deny, f"reverse shell not hard-blocked: {case['command']!r}"
