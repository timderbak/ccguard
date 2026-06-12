"""Chain-engine constants (ТЗ-09): the event → kill-chain STAGE bridge.

The chain engine correlates over STAGES, so for every event it must know which
stage(s) the event belongs to. Events carry only signal IDs (``signals_json``,
from the agent catalog). There is no signal→tactic link in the schema, so this
module provides a curated, server-side resolver.

Design choices:
  * Resolve signal → stage by PREFIX family. Signal IDs are tactic-aligned by
    naming convention (``cred.read.*``, ``egress.*``, ``fs.write.*``), so a
    prefix map is complete and stable, and needs NO change to ToolUseEvent and
    NO coupling to the agent catalog.
  * The stage vocabulary is the SAME kill-chain vocabulary used by
    ``Technique.tactic`` / ``data/techniques_seed.yaml`` and by the scenario
    steps — so a step ``tactic: exfiltration`` matches an ``egress.*`` event.
  * Most-specific prefix wins (ordered list), so ``discovery.secret_grep``
    (credential-access) is not swallowed by the generic ``discovery.*`` rule.

This is the ТЗ-08-faithful "event → signal → stage" path, encoded as data: each
family is grounded in the representative technique whose ``tactic`` it inherits.
NOTE: ``impact`` (ТЗ-IMPACT) and, as of P2, ``defense-evasion`` /
``command-and-control`` / ``lateral-movement`` are ALL mapped — adding the
catalog signals + these prefix entries revives each stage with zero
chain_engine change (the data-driven promise). No endpoint kill-chain stage is
structurally dead anymore.
"""
from __future__ import annotations

# Rule-id prefix for chain findings: the per-scenario rule_id is
# f"{CHAIN_RULE_PREFIX}{scenario_key}" (e.g. "ioa.chain.recon_to_exfil").
CHAIN_RULE_PREFIX: str = "ioa.chain."

# Lookback for loading events to correlate (reuses the sequence setting key when
# present; this is the fallback default). Scenarios cap themselves further via
# their own window_seconds.
DEFAULT_LOOKBACK_HOURS: float = 24.0

# Ordered (most-specific first) signal-prefix → kill-chain stage. First match
# wins. Grounded in the ТЗ-08 technique tactics:
_SIGNAL_STAGE_RULES: tuple[tuple[str, str], ...] = (
    # initial-access: indirect prompt injection (AML.T0051) + supply-chain entry
    # (T1195 / AML.T0010 / ASI04 are all initial-access in the seed).
    ("content.read.external", "initial-access"),
    ("pkg.publish", "initial-access"),
    # credential-access: secret reads + cloud-metadata + secret discovery
    # (T1552.* / T1555.* — credential-access).
    ("recon.cloud_metadata", "credential-access"),
    ("discovery.secret_grep", "credential-access"),
    ("cred.read.", "credential-access"),
    # discovery: host/network recon (T1033 / T1046) — no scenario uses it today,
    # but classified for completeness so it never mis-buckets.
    ("discovery.network_scan", "discovery"),
    ("discovery.recon", "discovery"),
    # P2: generic discovery fallback (cloud/account enum). Placed AFTER the
    # specific discovery.secret_grep (credential-access) above so that one wins.
    ("discovery.", "discovery"),
    # exfiltration: any egress channel (T1567 / T1048 / T1041 / AML.T0024).
    ("cloud.exfil.", "exfiltration"),
    ("egress.", "exfiltration"),
    # collection / staging: dedicated archive/capture IOAs (T1560/T1113/T1115,
    # P2-width-3) + the weak local-file-write markers (T1074).
    ("collection.", "collection"),
    ("fs.write.", "collection"),
    # execution: shell / eval / decode (T1059.*).
    ("exec.", "execution"),
    # persistence: rc/cron/systemd/launchd + agent-settings edit (T1546.* etc.).
    ("config.agent_settings_edit", "persistence"),
    ("persist.", "persistence"),
    # privilege-escalation: chmod/sudo/hosts/container-escape (T1548.* etc.).
    ("system.", "privilege-escalation"),
    ("container.", "privilege-escalation"),
    # impact: data destruction (T1485) — ТЗ-IMPACT. Adding this entry alone
    # revives poison_to_destructive (its impact step now resolves), with NO
    # chain_engine change — the data-driven promise made concrete.
    ("impact.", "impact"),
    # defense-evasion (P2): tamper with the EDR/security tooling, clear shell
    # history / system logs (T1562.* / T1070.*).
    ("defense.", "defense-evasion"),
    # command-and-control (P2): reverse shells + outbound tunnels (T1071/T1572).
    ("c2.", "command-and-control"),
    # lateral-movement (P2): remote command execution to another host (T1021.*).
    ("lateral.", "lateral-movement"),
)


# Canonical kill-chain stage progression (MITRE ATT&CK tactic order) for stable,
# legible UI ordering — alphabetical stage lists read as noise. OWASP risk-layer
# stages slot into their nearest kill-chain stage; ATLAS ML-internal stages (which
# an endpoint EDR can't reach) trail the endpoint chain. Stages absent here fall
# back to alphabetical after the known ones, so an unmapped stage never crashes.
KILL_CHAIN_ORDER: tuple[str, ...] = (
    "initial-access",
    "execution",
    "persistence",
    "privilege-escalation",
    "defense-evasion",
    "credential-access",
    "discovery",
    "lateral-movement",
    "collection",
    "command-and-control",
    "exfiltration",
    "impact",
    # ATLAS model-internal stages — structurally out-of-scope, shown last.
    "ml-model-access",
    "ml-attack-staging",
)


def stage_rank(tactic: str) -> int:
    """Sort key for a stage in kill-chain order; unknown stages sort last."""
    try:
        return KILL_CHAIN_ORDER.index(tactic)
    except ValueError:
        return len(KILL_CHAIN_ORDER)


def stage_for_signal(signal: str) -> str | None:
    """Resolve one signal ID to its kill-chain stage, or None if unmapped."""
    for prefix, stage in _SIGNAL_STAGE_RULES:
        if signal == prefix or signal.startswith(prefix):
            return stage
    return None


def stages_for_signals(signals: object) -> set[str]:
    """All kill-chain stages an event belongs to, from its signal list."""
    out: set[str] = set()
    if not isinstance(signals, (list, tuple)):
        return out
    for sig in signals:
        stage = stage_for_signal(str(sig))
        if stage is not None:
            out.add(stage)
    return out
