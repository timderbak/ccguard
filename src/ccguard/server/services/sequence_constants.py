"""Sequence detector constants (Behavioral Detection, Stage 3).

The IOA exfil-sequence detector fires when a ``cred.read.*`` signal is followed
by an ``egress.*`` signal on the same machine within
``sequence.window_minutes`` (SettingsRecord, tunable without redeploy).

The catalog prefixes here MUST match the per-event signal IDs in
``ccguard.agent.signals.catalog``; a unit test guards against drift.
"""
from __future__ import annotations

SEQUENCE_RULE_ID: str = "ioa.exfil_sequence"

DEFAULT_WINDOW_MINUTES: float = 15.0
DEFAULT_LOOKBACK_HOURS: float = 24.0

CRED_PREFIX: str = "cred.read."
EGRESS_PREFIX: str = "egress."

# --- ТЗ-02: staging-chain (trigger → staging-write [→ egress]) -------------
# ONE additional pattern, not a generic engine. The first link is any
# sensitive/recon read; the middle link is a staging write. egress is OPTIONAL
# (staging exfil is often deferred) — its presence only raises severity.
STAGING_RULE_ID: str = "ioa.staging_chain"

# First-link trigger prefixes. 0.2 ELSE branch: no dedicated "external content"
# signal exists yet, so the trigger is any sensitive-read / recon signal. An
# external-content signal is a TODO for a future ТЗ (would sharpen link #1).
STAGING_TRIGGER_PREFIXES: tuple[str, ...] = ("cred.read.", "recon.")

# Middle-link staging-write signal IDs (from agent catalog, ТЗ-02 §1).
STAGING_HIDDEN_SIGNAL: str = "fs.write.hidden"
STAGING_NORMAL_SIGNAL: str = "fs.write.normal"

# ТЗ-03: external-content read. When the staging chain's first link carries this
# signal it is the IPI signature (external content initiated the chain) — the
# orchestrator upgrades severity. It is also a VALID trigger on its own, but
# stays OPTIONAL: a chain without it still matches at its ТЗ-02 severity.
EXTERNAL_CONTENT_SIGNAL: str = "content.read.external"

# --- ТЗ-04: noise suppression (allowlist) + additive scoring ----------------
# A staging match whose WRITE event carries one of these benign-category markers
# is build/package noise (npm/pip/cargo/pytest/git) — suppressed (logged as
# info under a separate rule_id, never block/warn). NARROW by design: only known
# caches/VCS. Secret/unusual hidden dirs (.ssh/.aws/.config) carry NO marker and
# stay fully detected — a miss is worse than a false positive.
ALLOWLISTED_WRITE_MARKERS: frozenset[str] = frozenset({"fs.write.cache", "fs.write.vcs"})

# Suppressed matches are written under this distinct rule_id so they (a) are
# transparently findable and (b) never share dedup state with real findings.
STAGING_SUPPRESSED_RULE_ID: str = "ioa.staging_chain.suppressed"

# Additive scoring defaults (tunable via SettingsRecord — see _load_staging_cfg).
# Calibrated so ТЗ-02/03 outcomes are preserved:
#   non-ext hidden, no egress  = HIDDEN(2)                 = 2 → warn
#   ext     hidden, no egress  = HIDDEN(2)+EXTERNAL(3)     = 5 → block
#   any     hidden, egress     = HIDDEN(2)+EGRESS(4)[+EXT] ≥ 6 → critical
#   non-ext normal, no egress  = 0                         → info (below warn)
DEFAULT_STAGING_WEIGHTS: dict[str, float] = {
    "external": 3.0,
    "hidden": 2.0,
    "egress": 4.0,
}
DEFAULT_STAGING_THRESHOLDS: dict[str, float] = {
    "warn": 2.0,
    "block": 5.0,
    "critical": 6.0,
}
