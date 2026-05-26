"""Backward-compat tests for Policy.prompt_injection section (Phase 5 / 05-01).

Verifies:
- Default values for PromptInjectionConfig + LlamaGuardConfig.
- Literal/range validation on enums and timeout_ms.
- `extra="ignore"` on new configs lets v0.1 / v0.2 agents tolerate future
  fields without raising ValidationError (round-trip safe).
- Policy YAML без секции prompt_injection парсится через default-фабрику.
"""

from __future__ import annotations

from datetime import datetime, timezone

import pytest
import yaml
from pydantic import ValidationError

from ccguard.schemas.policy import (
    LlamaGuardConfig,
    Policy,
    PolicyMeta,
    PromptInjectionConfig,
)


def _meta() -> PolicyMeta:
    return PolicyMeta(revision=1, updated_at=datetime(2026, 5, 26, tzinfo=timezone.utc))


def test_prompt_injection_defaults() -> None:
    """Test 1: дефолты PromptInjectionConfig внутри Policy()."""
    p = Policy(meta=_meta())
    assert p.prompt_injection.enabled is True
    assert p.prompt_injection.severity == "warn"
    assert p.prompt_injection.regex_patterns == []
    assert p.prompt_injection.allowlist_patterns == []
    assert p.prompt_injection.llama_guard.enabled is False


def test_llama_guard_defaults() -> None:
    """Test 2: LlamaGuardConfig дефолты."""
    lg = LlamaGuardConfig()
    assert lg.enabled is False
    assert lg.endpoint == "http://localhost:11434"
    assert lg.model == "llama-guard3:8b"
    assert lg.timeout_ms == 500


def test_llama_guard_timeout_bounds() -> None:
    """Test 3: timeout_ms ∈ [50, 10000]."""
    # Invalid: below lower bound
    with pytest.raises(ValidationError):
        LlamaGuardConfig(timeout_ms=49)
    # Invalid: above upper bound
    with pytest.raises(ValidationError):
        LlamaGuardConfig(timeout_ms=10001)
    # Valid edges
    assert LlamaGuardConfig(timeout_ms=50).timeout_ms == 50
    assert LlamaGuardConfig(timeout_ms=10000).timeout_ms == 10000


def test_prompt_injection_severity_literal() -> None:
    """Test 4: severity ∈ Literal['info','warn','block']."""
    assert PromptInjectionConfig(severity="block").severity == "block"
    assert PromptInjectionConfig(severity="info").severity == "info"
    with pytest.raises(ValidationError):
        PromptInjectionConfig(severity="bogus")


def test_prompt_injection_extra_ignore_round_trip() -> None:
    """Test 5: future_field на новых конфигах молча игнорится (extra=ignore).

    Имитирует ситуацию когда v0.2 server отправляет policy с расширенной
    секцией, а агент с этой версией Pydantic-схемы должен её принять.
    """
    yaml_text = """
meta:
  schema_version: 1
  revision: 7
  name: default
  updated_at: 2026-05-26T00:00:00Z
prompt_injection:
  enabled: true
  severity: block
  regex_patterns: ["foo"]
  future_field: "x"
  llama_guard:
    enabled: true
    future_llama_field: 42
"""
    data = yaml.safe_load(yaml_text)
    p = Policy.model_validate(data)
    assert p.prompt_injection.severity == "block"
    assert p.prompt_injection.regex_patterns == ["foo"]
    assert p.prompt_injection.llama_guard.enabled is True

    # Round-trip: serialize then re-parse — extra fields are gone but core data preserved.
    dumped = yaml.safe_dump(p.model_dump(mode="json"))
    p2 = Policy.model_validate(yaml.safe_load(dumped))
    assert p2.prompt_injection.severity == "block"
    assert p2.prompt_injection.regex_patterns == ["foo"]
    assert p2.prompt_injection.llama_guard.enabled is True


def test_policy_without_prompt_injection_section() -> None:
    """Test 6: Policy YAML без prompt_injection → поле через default-фабрику."""
    yaml_text = """
meta:
  schema_version: 1
  revision: 1
  name: default
  updated_at: 2026-05-26T00:00:00Z
"""
    data = yaml.safe_load(yaml_text)
    p = Policy.model_validate(data)
    # Default factory kicked in.
    assert p.prompt_injection.enabled is True
    assert p.prompt_injection.severity == "warn"
    assert p.prompt_injection.regex_patterns == []
    assert p.prompt_injection.llama_guard.endpoint == "http://localhost:11434"
