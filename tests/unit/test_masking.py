"""Маскирование секретов в строках."""

from __future__ import annotations

from ccguard.agent.masking import mask_secrets


def test_none_passthrough() -> None:
    assert mask_secrets(None) is None


def test_no_secret_unchanged() -> None:
    assert mask_secrets("ls -la /tmp") == "ls -la /tmp"


def test_openai_key_masked() -> None:
    src = "export OPENAI_KEY=sk-abcdef0123456789ABCDEF0123"
    out = mask_secrets(src) or ""
    assert "sk-abcdef" not in out
    assert "***MASKED***" in out


def test_anthropic_key_masked() -> None:
    src = "ANTHROPIC=sk-ant-aaa_bbb_ccc_ddd_eee_fff_ggg"
    out = mask_secrets(src) or ""
    assert "sk-ant-" not in out


def test_github_pat_masked() -> None:
    out = mask_secrets("token: ghp_aaaaaaaaaaaaaaaaaaaa1234") or ""
    assert "ghp_aaaa" not in out


def test_aws_key_masked() -> None:
    out = mask_secrets("export AWS_KEY=AKIAIOSFODNN7EXAMPLE") or ""
    assert "AKIA" not in out


def test_jwt_masked() -> None:
    jwt = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4ifQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
    out = mask_secrets(jwt) or ""
    assert "eyJh" not in out


def test_password_kv_masked() -> None:
    out = mask_secrets("password=supersecret123") or ""
    assert "supersecret" not in out


def test_long_value_truncated() -> None:
    src = "x" * 500
    out = mask_secrets(src) or ""
    assert len(out) <= 220
    assert out.endswith("[truncated]")
