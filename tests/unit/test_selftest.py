"""Guard for `ccguard selftest` — the enforce hot-path battery must stay green.

If any never-legitimate action stops being denied by the hard tier, or a benign
dev command starts being blocked, this fails — that's the whole point of the
self-test, and this test makes it a CI gate too (not just a manual command).
"""
from __future__ import annotations

from ccguard.agent.selftest import CASES, run_selftest


def test_selftest_battery_all_pass():
    results, ok = run_selftest()
    failures = [r.case.name for r in results if not r.ok]
    assert ok, f"enforce self-test regressions: {failures}"


def test_selftest_denies_are_hard_tier():
    """Every evil case is caught by the ALWAYS-ON hard tier (works even with no
    policy) — not by a policy rule that could be flipped to observe/removed."""
    results, _ = run_selftest()
    for r in results:
        if r.case.expect == "deny":
            assert r.permission == "deny", r.case.name
            assert (r.rule_id or "").startswith("hard."), (r.case.name, r.rule_id)


def test_selftest_covers_both_verdicts():
    expects = {c.expect for c in CASES}
    assert expects == {"deny", "allow"}          # both sides exercised
    assert sum(c.expect == "deny" for c in CASES) >= 5   # a real evil battery
    assert sum(c.expect == "allow" for c in CASES) >= 5  # real FP-safety coverage
