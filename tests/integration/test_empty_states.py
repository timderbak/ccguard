"""Empty-state UX: пустой инстанс должен показывать понятные CTA, а не молчать.

Часть блокера BACKLOG §1 (Demo data cleanup). Эти тесты гарантируют, что:

- /admin/machines на свежей БД показывает "Пока ни одной машины" + CTA
  на /admin/install-agent (а не голую таблицу с подписью "Машины (0)").
- /admin (overview) рендерится без падения и тоже зовёт поставить агент.
- /admin/install-agent отдаёт 200 со страницей инструкции.

Snapshot/exact-markup проверок намеренно избегаем (см. memory/project_ui_redesign.md),
ассертим только смысловые маркеры.
"""
from __future__ import annotations

from fastapi.testclient import TestClient
from sqlmodel import Session

from ccguard.server.main import create_app
from ccguard.server.services.auth_service import create_session, hash_password


def _login(monkeypatch, tmp_path, db_name: str = "empty.db") -> tuple[TestClient, str]:
    monkeypatch.setenv("CCGUARD_ADMIN_PASSWORD_HASH", hash_password("hunter2"))
    monkeypatch.setenv("CCGUARD_DB_URL", f"sqlite:///{tmp_path}/{db_name}")
    monkeypatch.setenv("CCGUARD_SESSION_SECRET", "test-empty")
    client = TestClient(create_app())
    client.__enter__()
    with Session(client.app.state.engine) as s:
        sid = create_session(s, user_id="admin")
    return client, sid


def test_machines_list_empty_state_shows_cta(monkeypatch, tmp_path):
    """Fresh DB → /machines shows the empty state + install CTA."""
    client, sid = _login(monkeypatch, tmp_path)
    try:
        r = client.get("/machines", cookies={"ccg_session": sid})
        assert r.status_code == 200
        body = r.text
        assert "Пока ни одной машины" in body
        assert "Установить агент" in body
        # CTA должна вести на инструкцию
        assert "/admin/install-agent" in body
    finally:
        client.__exit__(None, None, None)


def test_overview_empty_renders_without_machines(monkeypatch, tmp_path):
    """Fresh DB → overview не падает, и показывает CTA про установку агента."""
    client, sid = _login(monkeypatch, tmp_path, db_name="empty-ov.db")
    try:
        r = client.get("/", cookies={"ccg_session": sid})
        assert r.status_code == 200
        body = r.text
        # Обзор тоже должен звать поставить агент, когда ничего нет.
        assert "/admin/install-agent" in body
        assert "Установить агент" in body
    finally:
        client.__exit__(None, None, None)


def test_install_agent_page_renders(monkeypatch, tmp_path):
    """/admin/install-agent → 200 + содержит ключевые секции инструкции."""
    client, sid = _login(monkeypatch, tmp_path, db_name="empty-inst.db")
    try:
        r = client.get("/admin/install-agent", cookies={"ccg_session": sid})
        assert r.status_code == 200
        body = r.text
        assert "Установка агента" in body
        # Хотя бы один из шагов локального запуска и один шаг про удалённый.
        assert "pip install" in body
        assert "ccguard install" in body
        # Где взять токен — ссылка на /settings.
        assert "/settings" in body
    finally:
        client.__exit__(None, None, None)


def test_install_agent_requires_session(monkeypatch, tmp_path):
    """Аноним без сессии → 307 на /login (так же, как остальные admin-маршруты)."""
    client, _ = _login(monkeypatch, tmp_path, db_name="empty-anon.db")
    try:
        r = client.get("/admin/install-agent", follow_redirects=False)
        assert r.status_code in (307, 401)
    finally:
        client.__exit__(None, None, None)
