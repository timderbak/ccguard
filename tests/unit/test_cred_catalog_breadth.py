"""P2: credential-access breadth — SaaS/cloud-CLI/DB creds + secret managers.

All map to the credential-access stage via the existing cred.read. prefix, so
they feed cred->egress and injection->cred->exfil chains with zero engine change.
"""
from __future__ import annotations

import pytest

from ccguard.agent.signals.extractor import extract_signals
from ccguard.server.services.chain_constants import stage_for_signal

SAAS = [
    "cat ~/.snowflake/credentials",
    "cat ~/.databricks-cfg",
    "cat ~/.dbt/profiles.yml",
    "cat ~/.terraform.d/credentials.tfrc.json",
    "cat ~/.pgpass",
    "cat ~/.my.cnf",
    "cat ~/.huggingface/token",
    "cat ~/.s3cfg",
]
SECRET_MGR = [
    "op item get 'AWS prod' --fields password",
    "op read op://vault/item/field",
    "bw get password github",
    "lpass show --password aws",
    "aws secretsmanager get-secret-value --secret-id prod/db",
    "gcloud secrets versions access latest --secret=api-key",
    "az keyvault secret show --name token --vault-name v",
    "az account get-access-token",
    "gcloud auth application-default print-access-token",
    "aws configure get aws_secret_access_key",
    "doppler secrets download --no-file",
    "sops -d secrets.enc.yaml",
]
OS_KEYCHAIN = [
    "security find-generic-password -s aws -w",
    "security dump-keychain",
    "secret-tool lookup service github",
    "keyring get aws default",
    "pass show prod/db",
    "gopass show api/key",
]


@pytest.mark.parametrize("cmd", SAAS)
def test_saas_token_fires(cmd):
    assert "cred.read.saas_token" in set(extract_signals("Bash", {"command": cmd})), cmd


@pytest.mark.parametrize("cmd", SECRET_MGR)
def test_secret_manager_fires(cmd):
    assert "cred.read.secret_manager" in set(extract_signals("Bash", {"command": cmd})), cmd


@pytest.mark.parametrize("cmd", OS_KEYCHAIN)
def test_os_keychain_fires(cmd):
    assert "cred.read.os_keychain" in set(extract_signals("Bash", {"command": cmd})), cmd


def test_new_cred_signals_map_to_credential_access():
    for sig in ("cred.read.saas_token", "cred.read.secret_manager", "cred.read.os_keychain"):
        assert stage_for_signal(sig) == "credential-access"


def test_benign_not_flagged():
    # a plain docker build / terraform plan is not a credential read; and
    # `doppler secrets set` (a WRITE) / bare `doppler secrets` (LIST) are not reads
    assert "cred.read.saas_token" not in set(
        extract_signals("Bash", {"command": "docker build -t app ."})
    )
    assert "cred.read.secret_manager" not in set(
        extract_signals("Bash", {"command": "terraform plan -out tf.plan"})
    )
    assert "cred.read.secret_manager" not in set(
        extract_signals("Bash", {"command": "doppler secrets set API_KEY=x"})
    )
