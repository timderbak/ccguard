"""Phase-3 wide regression tripwires (Plan 03-06 Task 2).

Three high-leverage assertions that catch silent scope/decision drift:

- ``test_phase_3_test_count_baseline``: ``pytest --collect-only`` reports ≥ 468
  tests. Phase 1+2 baseline = 443, Phase 3 added ≥ 25 net new tests
  (current count is materially higher than 468; the floor is intentionally
  conservative so refactors that delete tests trip this assertion before they
  hit code review). T-03-17 mitigation.
- ``test_severity_critical_round_trip``: D-01 ladder stays additive — the
  pre-Phase-3 severities (info/warn/block) still validate AND the new
  ``critical`` value validates through the same Pydantic Finding schema.
- ``test_haiku_pricing_constant_locked``: D-06 — input/output cents-per-MTok
  literals match Haiku 4.5 pricing. Tripwire against accidentally reverting to
  retired Haiku 3.5 rates.
"""

from __future__ import annotations

import re
import subprocess
import sys

import pytest

from ccguard.schemas.finding import Finding
from ccguard.server.services.llm_client import (
    INPUT_CENTS_PER_MTOK,
    MODEL,
    OUTPUT_CENTS_PER_MTOK,
)


# --- D-06 pricing tripwire -------------------------------------------------


def test_haiku_pricing_constant_locked() -> None:
    """Haiku 4.5: $1/MTok input, $5/MTok output. If anyone reverts to the
    retired Haiku 3.5 rates (25¢/$1.25) this assertion trips immediately."""
    assert INPUT_CENTS_PER_MTOK == 100, "input rate must be $1/MTok (Haiku 4.5)"
    assert OUTPUT_CENTS_PER_MTOK == 500, "output rate must be $5/MTok (Haiku 4.5)"
    assert MODEL == "claude-haiku-4-5-20251001"


# --- D-01 critical severity round-trip --------------------------------------


def test_severity_critical_round_trip() -> None:
    """Phase 1+2 severities still valid AND Phase 3 ``critical`` added."""
    # Phase 1+2 contract: info, warn, block still validate.
    for sev in ("info", "warn", "block"):
        f = Finding(
            rule_id="r",
            severity=sev,  # type: ignore[arg-type]
            title="t",
            description="d",
            source="s",
            recommendation="rec",
        )
        assert f.severity == sev
        # Round-trip through model_dump → model_validate.
        round_tripped = Finding.model_validate(f.model_dump())
        assert round_tripped.severity == sev

    # Phase 3 addition: critical validates and round-trips.
    f_c = Finding(
        rule_id="llm.scan.jailbreak",
        severity="critical",
        title="t",
        description="d",
        source="llm_scanner",
        recommendation="rec",
    )
    assert f_c.severity == "critical"
    rt = Finding.model_validate(f_c.model_dump())
    assert rt.severity == "critical"


# --- Test-count tripwire (T-03-17) -----------------------------------------


@pytest.mark.skipif(sys.platform == "win32", reason="subprocess pytest flaky on Windows CI")
def test_phase_3_test_count_baseline() -> None:
    """Trip if total collected test count drops below 468.

    Phase 1+2 baseline 443 + Phase 3 minimum 25 → 468. Current actual count is
    materially higher; this floor catches silent suite reductions (deleted
    test modules, parametrize collapses) before review.
    """
    result = subprocess.run(
        [sys.executable, "-m", "pytest", "--collect-only"],
        capture_output=True,
        text=True,
        check=False,
    )
    # pytest prints "<N> tests collected in <t>s" on success; "<N> tests
    # collected, <M> errors" on partial. Either way the count is in the stdout
    # summary block.
    combined = (result.stdout or "") + (result.stderr or "")
    match = re.search(r"(\d+)\s+tests?\s+collected", combined)
    assert match is not None, (
        f"could not locate 'N tests collected' in pytest output:\n{combined[-1000:]}"
    )
    count = int(match.group(1))
    assert count >= 468, (
        f"test suite shrank below floor: collected={count}, floor=468 (Phase 1+2 "
        "baseline 443 + Phase 3 minimum 25)"
    )
