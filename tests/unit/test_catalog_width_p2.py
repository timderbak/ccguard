"""P2 width pass: cloud-session creds, cloud/account enum, ssh-authorized_keys
persistence, PowerShell-encoded exec. Each maps to its stage via prefix."""
from __future__ import annotations

import pytest

from ccguard.agent.signals.extractor import extract_signals
from ccguard.server.services.chain_constants import stage_for_signal

CASES = [
    ("cat ~/.aws/sso/cache/abc.json", "cred.read.cloud_session", "credential-access"),
    ("cat /var/run/secrets/kubernetes.io/serviceaccount/token", "cred.read.cloud_session", "credential-access"),
    ("gcloud auth print-access-token", "cred.read.cloud_session", "credential-access"),
    ("aws iam list-users", "discovery.cloud_enum", "discovery"),
    ("kubectl get secrets --all-namespaces", "discovery.cloud_enum", "discovery"),
    ("getent passwd", "discovery.account_enum", "discovery"),
    ("cat /etc/passwd", "discovery.account_enum", "discovery"),
    ("echo 'ssh-ed25519 AAAA... attacker' >> ~/.ssh/authorized_keys", "persist.ssh_authorized_keys", "persistence"),
    ("powershell -enc SQBFAFgAIAAoAE4AZQB3AC0A", "exec.powershell_encoded", "execution"),
]


@pytest.mark.parametrize("cmd,sig,stage", CASES)
def test_signal_fires_and_maps(cmd, sig, stage):
    assert sig in set(extract_signals("Bash", {"command": cmd})), cmd
    assert stage_for_signal(sig) == stage


def test_discovery_secret_grep_still_maps_to_credential_access():
    # the new generic discovery. prefix must not steal secret_grep
    assert stage_for_signal("discovery.secret_grep") == "credential-access"


def test_benign_not_flagged():
    assert "discovery.account_enum" not in set(
        extract_signals("Bash", {"command": "cat /etc/hostname"})
    )
    assert "exec.powershell_encoded" not in set(
        extract_signals("Bash", {"command": "powershell -Command Get-Date"})
    )
