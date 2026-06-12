"""Constants for the low-and-slow kill-chain accumulator (P7-depth).

The tight-window correlators (``sequence_service`` ~minutes, ``chain_engine``
~minutes-to-hours) miss an attacker who deliberately spreads the kill chain
across DAYS — read credentials Monday, exfiltrate Wednesday, cover tracks
Friday. Each step is invisible to a window matcher.

``slow_chain_service`` closes that gap with a different signature: over a long
lookback, count how many DISTINCT *advanced* kill-chain stages a machine has
touched, regardless of spacing. Routine development rarely touches three of the
"right side" stages (credential-access, exfiltration, C2, defense-evasion,
lateral-movement, persistence, privilege-escalation, impact) in two weeks; an
attack does, fast OR slow.

The ``MIN_SPAN`` gate keeps this engine COMPLEMENTARY to the tight-window ones:
if all the distinct advanced stages happened inside a short burst, the fast
correlators already own it and slow_chain stays quiet.

All thresholds are overridable via ``SettingsRecord`` so the SOC can tune posture
without a redeploy.
"""
from __future__ import annotations

# The "right side" of the kill chain — stages that are rarely all-benign in
# routine development. impact (data destruction) and privilege-escalation join
# the set in P2-width-3: both are fed by dedicated, low-base-rate signals
# (impact.* is sensitive-target-gated; system.*/container.* are sudo-NOPASSWD /
# setuid / container-escape), so the ≥3-distinct + multi-hour-span gate keeps
# false positives low. collection stays OUT on purpose — it is fed by the
# ubiquitous fs.write.* markers (every project write), which would fire slow_chain
# on routine development.
ADVANCED_STAGES: frozenset[str] = frozenset(
    {
        "credential-access",
        "exfiltration",
        "command-and-control",
        "defense-evasion",
        "lateral-movement",
        "persistence",
        "privilege-escalation",
        "impact",
    }
)

# Long horizon — matches the anomaly baseline window so "low and slow" really
# means days, not the hours the chain engine already covers.
DEFAULT_LOOKBACK_DAYS: float = 14.0

# Escalate when this many DISTINCT advanced stages appear in the lookback.
DEFAULT_MIN_DISTINCT_STAGES: int = 3

# Require the advanced-stage activity to SPAN at least this long, so a fast
# burst (already caught by chain/sequence) does not double-fire here.
DEFAULT_MIN_SPAN_HOURS: float = 1.0

SLOW_CHAIN_RULE_ID: str = "ioa.slow_chain"
SLOW_CHAIN_SEVERITY: str = "warn"

# SettingsRecord keys for runtime tuning.
SETTING_LOOKBACK_DAYS: str = "slow_chain.lookback_days"
SETTING_MIN_STAGES: str = "slow_chain.min_distinct_stages"
SETTING_MIN_SPAN_HOURS: str = "slow_chain.min_span_hours"
