"""Эталон песочницы: асимметричный детект ОСЛАБЛЕНИЯ периметра.

Проверяются свойства, ради которых фича существует:

* первый контакт тихий — иначе подключение машины с уже настроенной песочницей
  завалило бы оператора находками;
* ослабление (выключили, расширили egress-allowlist, разрешили команды в обход,
  сняли fail-closed) → находка sandbox.weakened;
* усиление (включили, сузили allowlist) → тихо, эталон двигается вперёд;
* полное снятие периметра (песочницу выключили целиком) → critical, а частичное
  ослабление → warn;
* повтор того же состояния не даёт второй находки (эталон уже сдвинут);
* агент без поля sandbox (None) — no-op (обратная совместимость).

Значения находок (severity, reasons) снимаем в локальные переменные ВНУТРИ
сессии до её закрытия: после выхода из ``with`` ORM-объекты отвязаны от сессии.
"""
from __future__ import annotations

import json

from sqlmodel import Session, select

from ccguard.schemas import SandboxState
from ccguard.server.db.models import SandboxBaseline
from ccguard.server.db.session import init_db, make_engine
from ccguard.server.services import sandbox_baseline_service as svc


def _engine():
    eng = make_engine("sqlite://")
    init_db(eng)
    return eng


def _row(s, mid="m1") -> SandboxBaseline | None:
    return s.exec(
        select(SandboxBaseline).where(SandboxBaseline.machine_id == mid)
    ).one_or_none()


def _transition(old: SandboxState, new: SandboxState) -> tuple[int, str | None, list[str]]:
    """Прогнать bootstrap(old) → new и вернуть (кол-во находок, severity, reasons).

    Всё снимаем внутри сессии, чтобы не ловить DetachedInstanceError.
    """
    eng = _engine()
    with Session(eng) as s:
        svc.update_and_detect(s, "m1", old)
        s.commit()
        f = svc.update_and_detect(s, "m1", new)
        n = len(f)
        sev = f[0].severity if f else None
        reasons = json.loads(f[0].payload_json)["reasons"] if f else []
        s.commit()
    return n, sev, reasons


# --- bootstrap / backward-compat -------------------------------------------


def test_first_contact_is_silent():
    eng = _engine()
    with Session(eng) as s:
        f = svc.update_and_detect(
            s, "m1", SandboxState(configured=True, enabled=True,
                                  network_allowed_domains=["a.com"]),
        )
        s.commit()
        row = _row(s)
        assert f == []
        assert row is not None
        assert row.configured is True
        assert row.enabled is True


def test_none_is_noop_backward_compat():
    # Агент v0.1/v0.2 песочницу не собирает — сервис ничего не трогает.
    eng = _engine()
    with Session(eng) as s:
        f = svc.update_and_detect(s, "m1", None)
        s.commit()
        assert f == []
        assert _row(s) is None


def test_only_one_row_per_machine():
    eng = _engine()
    with Session(eng) as s:
        svc.update_and_detect(s, "m1", SandboxState(configured=True, enabled=True))
        s.commit()
        svc.update_and_detect(s, "m1", SandboxState(configured=True, enabled=False))
        s.commit()
        rows = list(s.exec(select(SandboxBaseline).where(SandboxBaseline.machine_id == "m1")))
        assert len(rows) == 1  # состояние единое, слот один


# --- ослабление → находка --------------------------------------------------


def test_disable_sandbox_is_critical():
    n, sev, reasons = _transition(
        SandboxState(configured=True, enabled=True),
        SandboxState(configured=True, enabled=False),
    )
    assert n == 1
    assert sev == "critical"  # периметр снят целиком
    assert any("выключена" in r for r in reasons)


def test_config_removed_is_critical():
    n, sev, reasons = _transition(
        SandboxState(configured=True, enabled=True),
        # sandbox-блок исчез целиком, остался лишь permissions.defaultMode
        SandboxState(configured=False, default_mode="default"),
    )
    assert n == 1
    assert sev == "critical"
    assert any("удалена" in r for r in reasons)


def test_egress_allowlist_expansion_is_warn():
    n, sev, reasons = _transition(
        SandboxState(configured=True, enabled=True, network_allowed_domains=["a.com"]),
        SandboxState(configured=True, enabled=True,
                     network_allowed_domains=["a.com", "evil.com"]),
    )
    assert n == 1
    assert sev == "warn"  # периметр цел, но egress расширен
    assert any("evil.com" in r for r in reasons)
    # a.com не должен помечаться «новым»
    assert not any("a.com" in r and "evil.com" not in r for r in reasons)


def test_allow_unsandboxed_and_fail_open_and_flags_warn():
    n, sev, reasons = _transition(
        SandboxState(configured=True, enabled=True, fail_if_unavailable=True,
                     allow_unsandboxed_commands=False, weaker_network_isolation=False),
        SandboxState(configured=True, enabled=True, fail_if_unavailable=False,
                     allow_unsandboxed_commands=True, weaker_network_isolation=True),
    )
    assert n == 1
    assert sev == "warn"
    joined = " | ".join(reasons)
    assert "fail-closed" in joined
    assert "обход" in joined
    assert "сетевая изоляция" in joined


def test_removing_deny_read_is_weakening():
    n, sev, reasons = _transition(
        SandboxState(configured=True, enabled=True, filesystem_deny_read=["~/.ssh", "~/.aws"]),
        SandboxState(configured=True, enabled=True, filesystem_deny_read=["~/.ssh"]),
    )
    assert n == 1
    assert any("~/.aws" in r for r in reasons)


def test_bypass_permissions_default_mode_is_weakening():
    n, sev, reasons = _transition(
        SandboxState(configured=True, enabled=True, default_mode="default"),
        SandboxState(configured=True, enabled=True, default_mode="bypassPermissions"),
    )
    assert n == 1
    assert any("bypassPermissions" in r for r in reasons)


# --- усиление / нейтральное → тихо -----------------------------------------


def test_enabling_egress_default_deny_is_not_weakening():
    # empty→allowlist+managedOnly — это УСИЛЕНИЕ (раскатка egress default-deny),
    # НЕ ослабление. Регрессия из security-review: раньше давало ложный
    # sandbox.weakened на усиливающем rollout.
    n, _, _ = _transition(
        SandboxState(configured=True, enabled=True),  # egress не ограничен
        SandboxState(configured=True, enabled=True,
                     network_allowed_domains=["api.anthropic.com", "pypi.org"],
                     network_allow_managed_domains_only=True),
    )
    assert n == 0


def test_expanding_active_allowlist_is_still_weakening():
    # А расширение УЖЕ активного default-deny (новый домен разрешён) — ослабление.
    n, sev, reasons = _transition(
        SandboxState(configured=True, enabled=True,
                     network_allowed_domains=["pypi.org"],
                     network_allow_managed_domains_only=True),
        SandboxState(configured=True, enabled=True,
                     network_allowed_domains=["pypi.org", "evil.com"],
                     network_allow_managed_domains_only=True),
    )
    assert n == 1
    assert any("evil.com" in r for r in reasons)


def test_strengthening_is_silent():
    eng = _engine()
    with Session(eng) as s:
        svc.update_and_detect(s, "m1", SandboxState(
            configured=True, enabled=False, network_allowed_domains=["a.com", "b.com"]))
        s.commit()
        # включили песочницу и сузили allowlist — усиление, находки быть не должно
        f = svc.update_and_detect(s, "m1", SandboxState(
            configured=True, enabled=True, network_allowed_domains=["a.com"]))
        s.commit()
        row = _row(s)
        assert f == []
        assert row.enabled is True  # эталон всё равно сдвинулся вперёд
        assert json.loads(row.state_json)["network_allowed_domains"] == ["a.com"]


def test_no_change_no_finding():
    eng = _engine()
    with Session(eng) as s:
        svc.update_and_detect(s, "m1", SandboxState(configured=True, enabled=False))
        s.commit()
        f1 = svc.update_and_detect(s, "m1", SandboxState(configured=True, enabled=False))
        s.commit()
        assert f1 == []


def test_weakening_then_repeat_no_second_finding():
    eng = _engine()
    with Session(eng) as s:
        svc.update_and_detect(s, "m1", SandboxState(configured=True, enabled=True))
        s.commit()
        f1 = svc.update_and_detect(s, "m1", SandboxState(configured=True, enabled=False))
        n1 = len(f1)
        s.commit()
        f2 = svc.update_and_detect(s, "m1", SandboxState(configured=True, enabled=False))
        n2 = len(f2)
        s.commit()
        assert n1 == 1
        assert n2 == 0  # эталон уже сдвинут — повтора нет


def test_detect_weakenings_pure_function():
    # Чистая функция сравнения — без БД, для ясности матрицы.
    assert svc.detect_weakenings({"enabled": True}, {"enabled": False}) == [
        "песочница выключена (sandbox.enabled=false)"
    ]
    assert svc.detect_weakenings({"enabled": False}, {"enabled": True}) == []  # усиление
    assert svc.detect_weakenings(
        {"network_allowed_domains": ["a"]}, {"network_allowed_domains": ["a"]}
    ) == []  # нет изменений
