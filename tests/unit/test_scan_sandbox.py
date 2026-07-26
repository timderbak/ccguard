"""scan_sandbox — извлечение эффективного состояния песочницы из settings.json.

Проверяем главное: слияние по приоритету scope (managed важнее user), отличие
«не задано» (None) от «выключено» (False), извлечение egress-allowlist и
ослабляющих флагов, и что при полном отсутствии песочницы возвращается None
(отчёт остаётся компактным, сервер не проверяет пустоту).
"""
from __future__ import annotations

from typing import Any

from ccguard.agent.scan.sandbox import scan_sandbox
from ccguard.agent.scan.settings import ParsedSettings
from ccguard.schemas import SettingsSource


def _ps(scope: str, data: dict[str, Any] | None) -> ParsedSettings:
    return ParsedSettings(
        source=SettingsSource(path=f"/x/{scope}.json", scope=scope, exists=True),
        data=data,
    )


# --- отсутствие / компактность --------------------------------------------


def test_no_sandbox_and_no_default_mode_returns_none():
    out = scan_sandbox([_ps("user", {"permissions": {"allow": ["Bash"]}})])
    assert out is None


def test_data_none_scope_is_skipped():
    # Битый/отсутствующий файл (data=None) не должен ронять сканер.
    out = scan_sandbox([
        _ps("user", None),
        _ps("project", {"sandbox": {"enabled": True}}),
    ])
    assert out is not None
    assert out.enabled is True
    assert out.configured is True


def test_default_mode_only_returns_state_but_not_configured():
    # bypassPermissions в конфиге без блока sandbox — всё равно важен.
    out = scan_sandbox([_ps("user", {"permissions": {"defaultMode": "bypassPermissions"}})])
    assert out is not None
    assert out.configured is False
    assert out.default_mode == "bypassPermissions"


# --- слияние по приоритету -------------------------------------------------


def test_managed_overrides_user_for_enabled():
    out = scan_sandbox([
        _ps("user", {"sandbox": {"enabled": False}}),
        _ps("managed", {"sandbox": {"enabled": True}}),
    ])
    assert out.enabled is True
    assert out.source_scope == "managed"


def test_per_field_priority_merge_keeps_unset_from_lower_scope():
    # managed задаёт только enabled; egress-allowlist из user должен сохраниться
    # (per-field override, а не «всё или ничего»).
    out = scan_sandbox([
        _ps("user", {"sandbox": {"enabled": True, "network": {"allowedDomains": ["a.com"]}}}),
        _ps("managed", {"sandbox": {"enabled": True}}),
    ])
    assert out.network_allowed_domains == ["a.com"]


def test_project_local_beats_project():
    out = scan_sandbox([
        _ps("project", {"sandbox": {"enabled": True}}),
        _ps("project_local", {"sandbox": {"enabled": False}}),
    ])
    assert out.enabled is False
    assert out.source_scope == "project_local"


# --- извлечение полей ------------------------------------------------------


def test_extracts_full_network_and_filesystem_and_flags():
    out = scan_sandbox([_ps("project", {"sandbox": {
        "enabled": True,
        "failIfUnavailable": True,
        "allowUnsandboxedCommands": False,
        "enableWeakerNestedSandbox": True,
        "enableWeakerNetworkIsolation": False,
        "excludedCommands": ["docker", "git"],
        "network": {
            "allowedDomains": ["api.example.com", "pypi.org"],
            "deniedDomains": ["evil.com"],
            "allowManagedDomainsOnly": True,
        },
        "filesystem": {
            "allowWrite": ["/tmp/work"],
            "denyRead": ["~/.ssh", "~/.aws"],
            "disabled": False,
        },
    }})])
    assert out.enabled is True
    assert out.fail_if_unavailable is True
    assert out.allow_unsandboxed_commands is False
    assert out.weaker_nested_sandbox is True
    assert out.weaker_network_isolation is False
    assert out.excluded_commands == ["docker", "git"]
    assert out.network_allowed_domains == ["api.example.com", "pypi.org"]
    assert out.network_denied_domains == ["evil.com"]
    assert out.network_allow_managed_domains_only is True
    assert out.filesystem_allow_write == ["/tmp/work"]
    assert out.filesystem_deny_read == ["~/.ssh", "~/.aws"]
    assert out.filesystem_disabled is False


def test_unset_bool_stays_none_not_false():
    # Пустой блок sandbox: configured=True, но enabled НЕ задан → None (важно
    # отличать «не задано» от «выключено» для детекта ослабления).
    out = scan_sandbox([_ps("user", {"sandbox": {}})])
    assert out.configured is True
    assert out.enabled is None
    assert out.fail_if_unavailable is None


def test_non_bool_enabled_is_ignored():
    # Строка "true" — не булев ключ; не угадываем truthy, иначе ложные срабатывания.
    out = scan_sandbox([_ps("user", {"sandbox": {"enabled": "true"}})])
    assert out.enabled is None
    assert out.configured is True


def test_non_list_allowed_domains_ignored():
    out = scan_sandbox([_ps("user", {"sandbox": {"network": {"allowedDomains": "a.com"}}})])
    assert out.network_allowed_domains == []
