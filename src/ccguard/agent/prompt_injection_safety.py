"""Shared ReDoS-safety utilities for prompt-injection admin patterns (CR-01).

The publish-time validator in :mod:`ccguard.server.web.policy_form` rejects
catastrophic-backtracking regex at admin form-submit. However, admin patterns
can also reach the agent via:

* hand-edited ``default_policy.yaml`` on the server (no UI gate)
* pre-Phase-5 policies migrated forward
* a future publish path that bypasses the form

This module provides a defense-in-depth gate so the PreToolUse hot path
cannot be wedged by a slow regex regardless of how it got into the policy.

Two layers mirror ``policy_form._redos_safe``:

1. **Structural check** — refuse the classic nested-quantifier shapes
   ``(X+)+``, ``(X*)+``, ``(X+)*``, ``(X*)*`` via a syntactic regex. Cheap,
   no input scan required.
2. **Adversarial probe** — run the compiled pattern against
   ``'a' * 30 + '!'`` on a worker thread with a 50ms wall-clock budget.
   Patterns that exceed the budget are dropped.

Both layers are intentional over-approximations: they reject a few safe
patterns to guarantee no catastrophic backtracker survives. This matches
the fail-open posture — admin custom patterns are best-effort, the default
catalog (which is curated and ReDoS-smoke-tested) is the authoritative
detection surface.
"""

from __future__ import annotations

import re

# Same structural detector as policy_form._REDOS_NESTED_QUANTIFIER_RE.
# Keep in sync if either side evolves.
_REDOS_NESTED_QUANTIFIER_RE = re.compile(r"\([^()]*[+*][^()]*\)[+*]")

# Adversarial probe — trailing literal forces a backtracking failure path
# on classics like ``^(a+)+$``.
_REDOS_PROBE = "a" * 30 + "!"

# Budget for the probe. Stays well below the 100ms PreToolUse SLA so even
# if a handful of admin patterns each consume their full budget, the total
# stays bounded. Compile-time cost only — paid once per
# ``_compiled_admin`` cache miss.
_REDOS_BUDGET_MS = 50


def is_structurally_unsafe(pattern: str) -> bool:
    """Return True if ``pattern`` matches the textbook nested-quantifier shape."""
    return bool(_REDOS_NESTED_QUANTIFIER_RE.search(pattern))


def probe_redos_safe(compiled: re.Pattern[str], budget_ms: int = _REDOS_BUDGET_MS) -> bool:
    """Return True if ``compiled.search(probe)`` returns within ``budget_ms``.

    Best-effort: patterns whose worst case does not align with our probe
    alphabet may slip through. Combined with :func:`is_structurally_unsafe`
    this catches the dominant ReDoS family.
    """
    from concurrent.futures import ThreadPoolExecutor
    from concurrent.futures import TimeoutError as FuturesTimeoutError

    with ThreadPoolExecutor(max_workers=1) as ex:
        fut = ex.submit(compiled.search, _REDOS_PROBE)
        try:
            fut.result(timeout=budget_ms / 1000.0)
            return True
        except FuturesTimeoutError:
            return False


__all__ = ["is_structurally_unsafe", "probe_redos_safe"]
