"""FastPolicy читает политику ровно как pydantic-Policy — это доказывается.

Горячий путь enforce читает политику через FastPolicy (без pydantic, ради
латентности). Малейшее расхождение с настоящей Policy — это либо пропущенная
блокировка, либо ложная. Поэтому здесь не «проверяем, что парсится», а
СВЕРЯЕМ каждое поле, которое enforce реально читает, между двумя путями.

Сценарий сверки повторяет прод: сервер отдаёт политику как ``model_dump`` (со
всеми дефолтами) → это попадает в кэш → FastPolicy читает кэш. Значит сверять
надо FastPolicy(нормализованный кэш) против исходной pydantic-Policy.
"""
from __future__ import annotations

from pathlib import Path

import yaml

from ccguard.agent.hot_policy import parse_fast_policy
from ccguard.schemas import Policy


def _normalized_cache_text(policy: Policy) -> str:
    """То, что сервер кладёт в кэш: model_dump полной политики."""
    return yaml.safe_dump(policy.model_dump(mode="json"))


def _minimal_policy() -> Policy:
    # Только обязательное (meta). Pydantic достроит ВСЕ защитные дефолты —
    # это и есть самый опасный случай: FastPolicy обязана увидеть их из
    # нормализованного кэша, а не потерять.
    return Policy.model_validate(
        {"meta": {"revision": 1, "updated_at": "2026-01-01T00:00:00Z"}}
    )


def _example_policy() -> Policy:
    path = Path(__file__).resolve().parents[2] / "examples" / "policy.example.yaml"
    return Policy.model_validate(yaml.safe_load(path.read_text()))


def _assert_rules_equal(fast_rules, pyd_rules, fields):
    fast_rules = fast_rules or []
    pyd_rules = pyd_rules or []
    assert len(fast_rules) == len(pyd_rules), "разное число правил"
    for fr, pr in zip(fast_rules, pyd_rules, strict=True):
        for f in fields:
            assert getattr(fr, f, None) == getattr(pr, f, None), f"правило.{f}"


def _assert_equivalent(policy: Policy) -> None:
    fast = parse_fast_policy(_normalized_cache_text(policy))
    assert fast is not None

    # --- топ-уровень ---
    assert fast.block_fail_mode == policy.block_fail_mode
    assert fast.enforcement_mode == policy.enforcement_mode

    # --- commands: защитные списки, которые дороже всего потерять ---
    fc, pc = fast.commands, policy.commands
    assert list(fc.denylist_patterns or []) == list(pc.denylist_patterns)
    assert list(fc.allowlist_patterns or []) == list(pc.allowlist_patterns)
    assert list(fc.always_deny or []) == list(pc.always_deny)
    _assert_rules_equal(
        fc.dangerous_patterns, pc.dangerous_patterns,
        ("id", "pattern", "type", "severity", "title", "reason", "remediation"),
    )

    # --- mcp_servers ---
    fm, pm = fast.mcp_servers, policy.mcp_servers
    assert list(fm.denylist_names or []) == list(pm.denylist_names)
    assert list(fm.allowlist_names or []) == list(pm.allowlist_names)
    assert list(fm.denylist_url_patterns or []) == list(pm.denylist_url_patterns)
    assert list(fm.allowlist_url_patterns or []) == list(pm.allowlist_url_patterns)
    assert bool(fm.deny_all_unknown) == bool(pm.deny_all_unknown)

    # --- network ---
    fn, pn = fast.network, policy.network
    assert list(fn.denylist_hosts or []) == list(pn.denylist_hosts)
    assert list(fn.allowlist_hosts or []) == list(pn.allowlist_hosts)
    assert bool(fn.deny_all_unknown) == bool(pn.deny_all_unknown)
    _assert_rules_equal(
        fn.suspicious_host_rules, pn.suspicious_host_rules,
        ("id", "pattern", "severity"),
    )


def test_minimal_policy_defaults_survive_the_fast_path():
    # Самый важный тест: на минимальной политике pydantic подставляет защитные
    # always_deny/dangerous_patterns. FastPolicy обязана увидеть их из
    # нормализованного кэша — иначе curl|sh прошёл бы незамеченным.
    pol = _minimal_policy()
    assert pol.commands.always_deny, "предохранитель теста: дефолты не пусты"
    assert pol.commands.dangerous_patterns
    _assert_equivalent(pol)


def test_example_policy_is_read_identically():
    _assert_equivalent(_example_policy())


def test_dangerous_pattern_fields_are_readable_as_attributes():
    # enforce читает rule.id / rule.pattern / rule.severity как атрибуты —
    # проверяем, что обёртка это действительно даёт, а не dict.
    fast = parse_fast_policy(_normalized_cache_text(_minimal_policy()))
    rules = fast.commands.dangerous_patterns
    assert rules
    r0 = rules[0]
    assert isinstance(r0.id, str)
    assert isinstance(r0.pattern, str)


def test_missing_and_broken_cache_return_none():
    from ccguard.agent.hot_policy import load_fast_policy
    assert load_fast_policy("/no/such/path/xyz.yaml") is None
    assert parse_fast_policy("this: is: not: valid: yaml:::") is None
    assert parse_fast_policy("[]") is None  # не объект — не политика
