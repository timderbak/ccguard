"""Risk engine constants (Behavioral Detection, Stage 2).

Per-signal weights, tunable defaults, and the canonical ``rule_id`` for the
``risk.elevated`` finding. All numerics are admin-tunable via ``SettingsRecord``
(``risk.threshold``, ``risk.window_hours``, ``risk.half_life_hours``,
``risk.weight.<signal_id>``); the values here are first-boot defaults only.

Weights reflect ATT&CK tactic severity: credential access + egress weigh higher
than recon. Calibration is expected to evolve with pilot data; the catalog of
*which* signals exist is locked, the numbers are not.
"""
from __future__ import annotations

RISK_RULE_ID: str = "risk.elevated"

DEFAULT_THRESHOLD: float = 10.0
DEFAULT_WINDOW_HOURS: float = 24.0
DEFAULT_HALF_LIFE_HOURS: float = 6.0

DEFAULT_WEIGHTS: dict[str, float] = {
    "cred.read.aws": 5.0,
    "cred.read.ssh": 5.0,
    "cred.read.dotenv": 3.0,
    "egress.network_tool": 4.0,
    "exec.pipe_to_shell": 4.0,
    "persist.shell_rc": 3.0,
    "persist.cron": 3.0,
    "discovery.recon": 1.0,
    # Stage 6 catalog expansion — calibrated against the same ATT&CK-tactic
    # severity axis: cloud-cred reads weigh on par with AWS/SSH; container
    # escape and cloud-storage exfil are direct attack primitives; package
    # publish and systemd persistence rank with shell-rc.
    "cred.read.gcp": 5.0,
    "cred.read.azure": 5.0,
    "cred.read.kube": 5.0,
    "cred.read.browser": 5.0,
    "cred.read.git": 4.0,
    "cloud.exfil.storage": 5.0,
    "container.escape_hint": 4.0,
    "pkg.publish": 3.0,
    "recon.cloud_metadata": 3.0,
    "persist.systemd": 3.0,
}
