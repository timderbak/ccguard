"""Declarative per-event signal catalog (Behavioral Detection, Stage 1).

Each :class:`Signal` is a single regex matched against a normalized text view
of one tool invocation (command + file path, lowercased). These are *per-event*
detections only; rate-based (burst) and stateful (sequence, config-drift)
detections live server-side in later stages.

ATT&CK / ATLAS mappings are part of the contract — the triage UI links each
fired signal to its technique. Keep IDs STABLE: they are persisted in
``ToolUseEvent.signals_json`` and referenced by the server-side risk engine.
"""
from __future__ import annotations

import re
from dataclasses import dataclass


@dataclass(frozen=True)
class Signal:
    """One per-event behavioral signal.

    ``pattern`` is matched (``search``) against the normalized text of a tool
    invocation. ``attack_technique`` is a MITRE ATT&CK id (``T####`` /
    ``T####.###``) or an ATLAS reference (``ATLAS.<name>``).
    """

    id: str
    attack_technique: str
    pattern: re.Pattern[str]
    description: str


def _p(rx: str) -> re.Pattern[str]:
    return re.compile(rx, re.IGNORECASE)


CATALOG: tuple[Signal, ...] = (
    Signal(
        "cred.read.aws",
        "T1552.001",
        _p(r"\.aws/(credentials|config)"),
        "Access to AWS credential files",
    ),
    Signal(
        "cred.read.ssh",
        "T1552.004",
        _p(r"(\.ssh/|\bid_rsa\b|\bid_ed25519\b)"),
        "Access to SSH private keys",
    ),
    Signal(
        "cred.read.dotenv",
        "T1552.001",
        _p(r"(\.env\b|\.npmrc\b|\.pypirc\b|\.pem\b|\.netrc\b)"),
        "Access to dotenv / package-manager / cert secrets",
    ),
    Signal(
        "egress.network_tool",
        "T1041",
        _p(r"\b(curl|wget|nc|ncat|scp|sftp)\b"),
        "Outbound transfer tool invoked",
    ),
    Signal(
        "exec.pipe_to_shell",
        "T1059.004",
        _p(r"(\|\s*(ba|z)?sh\b|base64\s+(-d|--decode)|\beval\b)"),
        "Piping/decoding into a shell interpreter",
    ),
    Signal(
        "persist.shell_rc",
        "T1546.004",
        _p(r"\.(bashrc|zshrc|bash_profile|profile)\b"),
        "Modification of shell startup files",
    ),
    Signal(
        "persist.cron",
        "T1053.003",
        _p(r"\bcrontab\b"),
        "Cron-based persistence",
    ),
    Signal(
        "discovery.recon",
        "T1033",
        _p(r"\b(whoami|uname|ifconfig|ip\s+addr|aws\s+sts\s+get-caller-identity)\b"),
        "Host/identity reconnaissance",
    ),
    # --- Behavioral Detection v2 Stage 6 (catalog expansion) ----------------
    Signal(
        "cred.read.gcp",
        "T1552.001",
        _p(r"(\.config/gcloud/|application_default_credentials\.json|\.boto\b)"),
        "Access to Google Cloud credential stores",
    ),
    Signal(
        "cred.read.azure",
        "T1552.001",
        _p(r"(\.azure/|azureprofile\.json|accesstokens\.json)"),
        "Access to Azure CLI credential stores",
    ),
    Signal(
        "cred.read.kube",
        "T1552.001",
        _p(r"(\.kube/config|\bkubeconfig\b)"),
        "Access to Kubernetes kubeconfig",
    ),
    Signal(
        "cred.read.browser",
        "T1555.003",
        _p(r"(login\s+data|cookies\.sqlite|cookies\.binarycookies|formhistory\.sqlite)"),
        "Access to browser credential / cookie stores",
    ),
    Signal(
        "cred.read.git",
        "T1552.001",
        _p(r"(\.git-credentials\b|gh\s+auth\s+token)"),
        "Access to git / GitHub CLI auth material",
    ),
    Signal(
        "cloud.exfil.storage",
        "T1567.002",
        _p(
            r"\b(aws\s+s3\s+(cp|sync)\s+\S+\s+s3://"
            r"|gsutil\s+cp\s+\S+\s+gs://"
            r"|az\s+storage\s+blob\s+upload)"
        ),
        "Cloud-storage write — exfiltration over web service",
    ),
    Signal(
        "container.escape_hint",
        "T1610",
        _p(r"(--privileged\b|/var/run/docker\.sock\b|\bnsenter\b|/proc/1/root)"),
        "Container-escape primitives",
    ),
    Signal(
        "pkg.publish",
        "T1195.002",
        _p(r"\b(npm\s+publish|twine\s+upload|cargo\s+publish|gem\s+push)\b"),
        "Package publish — supply-chain typosquatting / dependency injection",
    ),
    Signal(
        "recon.cloud_metadata",
        "T1552.005",
        _p(r"\b169\.254\.169\.254\b"),
        "Cloud instance-metadata endpoint access",
    ),
    Signal(
        "persist.systemd",
        "T1543.002",
        _p(r"(\.config/systemd/user/|systemctl\s+--user\s+(enable|start))"),
        "User-level systemd unit persistence",
    ),
)
