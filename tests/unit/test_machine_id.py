"""machine_id: стабильность + изоляция через salt."""

from __future__ import annotations

from ccguard.agent.machine_id import derive_machine_id


def test_stable_across_calls() -> None:
    a = derive_machine_id("salt-abc", uid=1000)
    b = derive_machine_id("salt-abc", uid=1000)
    assert a == b


def test_different_salt_different_id() -> None:
    a = derive_machine_id("salt-abc", uid=1000)
    b = derive_machine_id("salt-xyz", uid=1000)
    assert a != b


def test_different_uid_different_id() -> None:
    a = derive_machine_id("salt-abc", uid=1000)
    b = derive_machine_id("salt-abc", uid=1001)
    assert a != b


def test_id_format_is_base32_lowercase() -> None:
    mid = derive_machine_id("salt", uid=0)
    # base32 lowercase, 128 бит → 26 символов (без паддинга после rstrip)
    assert mid.islower()
    assert all(c in "abcdefghijklmnopqrstuvwxyz234567" for c in mid)
    assert 25 <= len(mid) <= 26
