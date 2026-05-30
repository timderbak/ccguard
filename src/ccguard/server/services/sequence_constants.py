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
