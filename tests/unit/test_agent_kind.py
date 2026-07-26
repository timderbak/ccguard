"""Фундамент мультиагентности: тип агента сквозь модель.

Проверяет то, ради чего поле заводилось:

* агент декларирует свой тип, сервер его хранит;
* старый агент (поле не шлёт) трактуется как claude_code — до сих пор другого
  не было, и это честный, а не выдуманный default;
* незнакомый тип агента принимается как есть (сервер graceful — новые агенты
  добавляются без изменения схемы).
"""
from __future__ import annotations

from datetime import UTC, datetime

from sqlmodel import Session

from ccguard.schemas import InventoryReport, SyncPayload
from ccguard.server.db.models import Machine
from ccguard.server.db.session import init_db, make_engine


def _inv(machine_id: str, **kw) -> InventoryReport:
    base = dict(
        machine_id=machine_id, machine_label="k", timestamp=datetime.now(UTC),
        agent_version="0.3.0", os="linux",
    )
    base.update(kw)
    return InventoryReport(**base)


def test_default_agent_kind_is_claude_code():
    # Отчёт без поля — старый агент. Единственный существовавший агент.
    inv = _inv("m1")
    assert inv.agent_kind == "claude_code"


def test_unknown_agent_kind_is_accepted():
    # Строка, а не Literal: новый агент не должен требовать правки схемы.
    inv = _inv("m1", agent_kind="some_future_agent")
    assert inv.agent_kind == "some_future_agent"


def test_serialization_roundtrip_keeps_kind():
    inv = _inv("m1", agent_kind="cursor")
    payload = SyncPayload(inventory=inv).model_dump(mode="json")
    back = SyncPayload.model_validate(payload)
    assert back.inventory.agent_kind == "cursor"


def test_old_payload_without_field_parses_as_claude_code():
    # Ровно то, что пришлёт агент v0.1/v0.2: JSON без agent_kind.
    raw = {
        "inventory": {
            "schema_version": 1, "machine_id": "m-old",
            "timestamp": datetime.now(UTC).isoformat(),
            "agent_version": "0.1.0", "os": "linux",
        }
    }
    back = SyncPayload.model_validate(raw)
    assert back.inventory.agent_kind == "claude_code"


def test_existing_db_rows_migrate_to_claude_code():
    # Машина, заведённая до колонки, должна получить claude_code, а не NULL:
    # других агентов в системе до сих пор не было — это честная миграция.
    eng = make_engine("sqlite://")
    init_db(eng)
    with Session(eng) as s:
        # Пишем машину напрямую, имитируя строку без явного agent_kind.
        m = Machine(machine_id="m-legacy", machine_label="legacy",
                    first_seen=datetime.now(UTC).replace(tzinfo=None),
                    last_seen=datetime.now(UTC).replace(tzinfo=None))
        s.add(m)
        s.commit()
        got = s.get(Machine, "m-legacy")
    assert got.agent_kind == "claude_code"
