"""TOFU-эталон памяти: доверие при первом контакте, затем детект дрейфа.

Проверяются свойства, ради которых фича существует:

* первый контакт с машиной тихий — иначе подключение машины, где CLAUDE.md уже
  есть, завалило бы оператора находками на пустом месте;
* после этого новый файл и изменение содержимого не проходят незаметно;
* появление инструкции ВНЕ репозитория (внешний @import, ancestor) отделено от
  рядовой правки — это разные по смыслу события;
* дрейф — warn, а не block: память правят постоянно, блокировка на каждую
  правку приучила бы игнорировать сигнал.
"""
from __future__ import annotations

from sqlmodel import Session, select

from ccguard.schemas.inventory import MemoryEntry
from ccguard.server.db.models import MemoryBaseline
from ccguard.server.db.session import init_db, make_engine
from ccguard.server.services import memory_baseline_service as svc


def _engine():
    eng = make_engine("sqlite://")
    init_db(eng)
    return eng


def _mem(path, h, scope="project", imported_by=None, size=100):
    return MemoryEntry(
        path=path, scope=scope, content_hash=h, size_bytes=size, imported_by=imported_by,
    )


def _rules(s, mid):
    return list(s.exec(select(MemoryBaseline).where(MemoryBaseline.machine_id == mid)))


def test_first_contact_is_silent():
    # Машина подключилась впервые: память уже есть, но находок быть не должно.
    eng = _engine()
    with Session(eng) as s:
        f = svc.update_and_detect(s, "m1", [
            _mem("/p/CLAUDE.md", "h1"),
            _mem("/u/CLAUDE.md", "h2", scope="user"),
        ])
        s.commit()
        rows = _rules(s, "m1")
    assert f == []
    assert len(rows) == 2
    assert all(r.status == "pending" for r in rows)


def test_new_file_after_bootstrap_warns():
    eng = _engine()
    with Session(eng) as s:
        svc.update_and_detect(s, "m1", [_mem("/p/CLAUDE.md", "h1")])
        svc.accept_all_pending(s, "m1", "op")
        s.commit()
        # Теперь появляется ещё один файл памяти.
        f = svc.update_and_detect(s, "m1", [
            _mem("/p/CLAUDE.md", "h1"),
            _mem("/p/sub/CLAUDE.md", "h9", scope="subdir"),
        ])
    assert [x.rule_id for x in f] == ["memory.new"]
    assert f[0].severity == "warn"


def test_external_import_is_flagged_separately():
    # Новый внешний импорт — не рядовая правка: инструкция вне репозитория.
    eng = _engine()
    with Session(eng) as s:
        svc.update_and_detect(s, "m1", [_mem("/p/CLAUDE.md", "h1")])
        svc.accept_all_pending(s, "m1", "op")
        s.commit()
        f = svc.update_and_detect(s, "m1", [
            _mem("/p/CLAUDE.md", "h1"),
            _mem("/home/u/evil.md", "hx", scope="import",
                 imported_by="/p/CLAUDE.md"),
        ])
    assert [x.rule_id for x in f] == ["memory.external"]
    assert "вне" in f[0].payload_json or "репозитор" in f[0].payload_json


def test_content_drift_warns_not_blocks():
    eng = _engine()
    with Session(eng) as s:
        svc.update_and_detect(s, "m1", [_mem("/p/CLAUDE.md", "h1")])
        svc.accept_all_pending(s, "m1", "op")
        s.commit()
        f = svc.update_and_detect(s, "m1", [_mem("/p/CLAUDE.md", "h2")])
    assert [x.rule_id for x in f] == ["memory.drift"]
    assert f[0].severity == "warn", "block на каждую правку памяти = шум"


def test_unchanged_content_is_silent():
    eng = _engine()
    with Session(eng) as s:
        svc.update_and_detect(s, "m1", [_mem("/p/CLAUDE.md", "h1")])
        svc.accept_all_pending(s, "m1", "op")
        s.commit()
        f = svc.update_and_detect(s, "m1", [_mem("/p/CLAUDE.md", "h1")])
    assert f == []


def test_accepted_file_removal_is_reported_once():
    eng = _engine()
    with Session(eng) as s:
        svc.update_and_detect(s, "m1", [
            _mem("/p/CLAUDE.md", "h1"),
            _mem("/p/other.md", "h2", scope="import", imported_by="/p/CLAUDE.md"),
        ])
        svc.accept_all_pending(s, "m1", "op")
        s.commit()
        # Один принятый файл исчез.
        f = svc.update_and_detect(s, "m1", [_mem("/p/CLAUDE.md", "h1")])
    assert [x.rule_id for x in f] == ["memory.removed"]


def test_returning_file_is_silent_recovery():
    eng = _engine()
    with Session(eng) as s:
        svc.update_and_detect(s, "m1", [
            _mem("/p/CLAUDE.md", "h1"), _mem("/p/x.md", "h2"),
        ])
        svc.accept_all_pending(s, "m1", "op")
        s.commit()
        svc.update_and_detect(s, "m1", [_mem("/p/CLAUDE.md", "h1")])  # x пропал
        s.commit()
        # x вернулся с тем же содержимым — тихо, без новой находки.
        f = svc.update_and_detect(s, "m1", [
            _mem("/p/CLAUDE.md", "h1"), _mem("/p/x.md", "h2"),
        ])
        rows = {r.path: r.status for r in _rules(s, "m1")}
    assert f == []
    assert rows["/p/x.md"] == "active"


def test_accept_reject_flow():
    eng = _engine()
    with Session(eng) as s:
        svc.update_and_detect(s, "m1", [_mem("/p/CLAUDE.md", "h1")])
        s.commit()
        row = _rules(s, "m1")[0]
        svc.accept_baseline(s, "m1", row.id, "op")
        s.commit()
        assert s.get(MemoryBaseline, row.id).status == "active"
        svc.reject_and_mark(s, "m1", row.id)
        s.commit()
        assert s.get(MemoryBaseline, row.id).status == "removed"


def test_old_agent_without_memory_field_is_noop():
    # Агент v0.1/v0.2 память не шлёт → пустой список. Это НЕ должно выглядеть как
    # «всё удалили»: иначе каждый sync старого агента ронял бы принятую память в
    # missing и спамил memory.removed. Пустой список = ничего не трогаем.
    eng = _engine()
    with Session(eng) as s:
        svc.update_and_detect(s, "m1", [_mem("/p/CLAUDE.md", "h1")])
        svc.accept_all_pending(s, "m1", "op")
        s.commit()
        f = svc.update_and_detect(s, "m1", [])  # старый агент: поля нет
        rows = {r.path: r.status for r in _rules(s, "m1")}
    assert f == [], "старый агент не должен порождать находок"
    assert rows["/p/CLAUDE.md"] == "active", "принятая память остаётся принятой"
