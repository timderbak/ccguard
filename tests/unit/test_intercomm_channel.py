"""ASI07: новый удалённый MCP-канал → intercomm.remote_channel.

Удалённый MCP (transport http/sse) — межагентный канал доверия агент→сервер.
Проверяем: на bootstrap машины молчим (иначе первое подключение с уже
настроенными удалёнными MCP шумело бы), после — появление НОВОГО удалённого
канала это находка; локальный (stdio) сервер каналом не считается; это НЕ дубль
rug-pull (тот про подмену описания/определения = ASI04).
"""
from __future__ import annotations

import json

from sqlmodel import Session, select

from ccguard.schemas import McpServerEntry
from ccguard.server.db.models import FindingRecord
from ccguard.server.db.session import init_db, make_engine
from ccguard.server.services import mcp_baseline_service as svc


def _engine():
    eng = make_engine("sqlite://")
    init_db(eng)
    return eng


def _mcp(name: str, transport: str = "stdio", url: str | None = None) -> McpServerEntry:
    return McpServerEntry(
        name=name, transport=transport, url=url, source=f"cfg:{name}",
    )


def _intercomm(session, mid="m1") -> list[FindingRecord]:
    return list(session.exec(
        select(FindingRecord).where(
            FindingRecord.machine_id == mid,
            FindingRecord.rule_id == "intercomm.remote_channel",
        )
    ))


def test_bootstrap_with_remote_mcp_is_silent():
    # Первое подключение: удалённый MCP уже настроен — не находка, только baseline.
    eng = _engine()
    with Session(eng) as s:
        f = svc.update_and_detect(s, "m1", [_mcp("remote", "sse", "https://a.io")])
        s.commit()
        assert [x for x in f if x.rule_id == "intercomm.remote_channel"] == []
        assert _intercomm(s) == []


def test_new_remote_channel_after_bootstrap_fires():
    eng = _engine()
    with Session(eng) as s:
        # bootstrap: локальный сервер уже есть.
        svc.update_and_detect(s, "m1", [_mcp("localfs", "stdio")])
        s.commit()
        # позже появился удалённый канал.
        f = svc.update_and_detect(s, "m1", [
            _mcp("localfs", "stdio"),
            _mcp("remote", "http", "http://mcp.vendor.io"),
        ])
        n = len([x for x in f if x.rule_id == "intercomm.remote_channel"])
        sev = next((x.severity for x in f if x.rule_id == "intercomm.remote_channel"), None)
        payloads = [json.loads(x.payload_json) for x in f if x.rule_id == "intercomm.remote_channel"]
        s.commit()
        assert n == 1
        assert sev == "warn"
        assert payloads[0]["transport"] == "http"
        assert payloads[0]["url"] == "http://mcp.vendor.io"


def test_new_stdio_server_is_not_a_channel():
    eng = _engine()
    with Session(eng) as s:
        svc.update_and_detect(s, "m1", [_mcp("a", "stdio")])
        s.commit()
        f = svc.update_and_detect(s, "m1", [_mcp("a", "stdio"), _mcp("b", "stdio")])
        s.commit()
        assert [x for x in f if x.rule_id == "intercomm.remote_channel"] == []


def test_channel_not_repeated_on_next_sync():
    eng = _engine()
    with Session(eng) as s:
        svc.update_and_detect(s, "m1", [_mcp("localfs", "stdio")])
        s.commit()
        svc.update_and_detect(s, "m1", [_mcp("localfs", "stdio"), _mcp("r", "sse", "https://a.io")])
        s.commit()
        # r уже в baseline — второй sync не должен повторять находку канала.
        f = svc.update_and_detect(s, "m1", [_mcp("localfs", "stdio"), _mcp("r", "sse", "https://a.io")])
        s.commit()
        assert [x for x in f if x.rule_id == "intercomm.remote_channel"] == []
