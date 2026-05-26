"""Latency budget assertion for prompt_injection_engine.scan() — Phase 5 / 05-02.

Enforces RESEARCH §"Latency budget": regex stage must stay <30 ms mean over
100 iterations on a 4096-byte input with 30 admin patterns plus the 15
default catalog entries. LlamaGuard is intentionally OUT of budget (its
timeout is the relevant SLO knob, not regex throughput).
"""

from __future__ import annotations

import time

from ccguard.agent.prompt_injection_engine import scan
from ccguard.schemas.policy import LlamaGuardConfig, PromptInjectionConfig

# Allow some headroom so the test is not flaky on a loaded CI runner while
# still catching catastrophic regressions (e.g., accidentally unbounded
# .* in the default catalog).
_BUDGET_SECONDS = 0.030


def test_regex_stage_under_30ms_mean_on_4kb_input() -> None:
    cfg = PromptInjectionConfig(
        enabled=True,
        regex_patterns=[f"benign_admin_{i}" for i in range(30)],
        llama_guard=LlamaGuardConfig(enabled=False),
    )
    # 4 KiB plain text that does NOT match any default or admin pattern,
    # which forces full scan of every regex (worst case for latency).
    text = "a" * 4096

    # Warm-up — primes lru_cache(_compiled_admin) and JIT-friendly paths.
    for _ in range(3):
        scan(text, cfg)

    iterations = 100
    start = time.perf_counter()
    for _ in range(iterations):
        scan(text, cfg)
    elapsed = time.perf_counter() - start

    mean = elapsed / iterations
    assert mean < _BUDGET_SECONDS, (
        f"regex-stage latency regressed: mean={mean * 1000:.2f}ms "
        f"(budget={_BUDGET_SECONDS * 1000:.0f}ms over {iterations} runs)"
    )
