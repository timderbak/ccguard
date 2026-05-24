# ccguard Web UI Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build a server-rendered web UI for ccguard so admins can view fleet status, manage findings, and edit/distribute policy through a Draft→Publish workflow.

**Architecture:** HTMX + Jinja2 + Tailwind layered on top of the existing FastAPI/SQLite server. Web routes use cookie sessions (`Depends(require_session)`); existing JSON API for agents keeps using `X-CCGuard-Token`. Three new SQL tables (`PolicyVersion`, `WebSession`, `AgentToken`) plus a thin service layer extracted from the existing handlers.

**Tech Stack:** Python 3.12, FastAPI, SQLModel, pydantic v2, jinja2, passlib[bcrypt], itsdangerous, python-multipart, HTMX, Tailwind (prebuilt).

**Spec:** `docs/superpowers/specs/2026-05-24-ccguard-web-ui-design.md`

**Phases (pause-friendly):**

| # | Phase | Outcome |
|---|---|---|
| 0 | Setup deps + skeleton | Empty `/login` page renders |
| 1 | Auth + session + CSRF | Login works, web vs API auth separated |
| 2 | DB models + service layer | `PolicyVersion`/`AgentToken`/`WebSession` migrated, services exist |
| 3 | PolicyLoader → DB | Agents read policy from DB, file becomes bootstrap |
| 4 | Overview page | Fleet table renders, polling works |
| 5 | Machines list + detail | Inventory view, revoke machine |
| 6 | Findings feed | Filters, pagination |
| 7 | Policy editor (form-only) | Draft → Publish flow |
| 8 | Policy history + rollback | Version list, diff view, rollback |
| 9 | Settings | Token CRUD, password change |
| 10 | Docker + E2E smoke | One docker-compose test |

After each phase: all tests pass, atomic commit, safe to pause.

---

## Phase 0: Setup dependencies and skeleton

**Goal:** Server boots, serves `/login` page (Jinja2 wired), Tailwind CSS available, tests still green.

### Task 0.1: Add new dependencies to pyproject.toml

**Files:**
- Modify: `pyproject.toml`

- [ ] **Step 1: Add new runtime deps**

In `pyproject.toml` find the `dependencies = [ ... ]` block and append:

```toml
    "jinja2>=3.1",
    "python-multipart>=0.0.9",
    "passlib[bcrypt]>=1.7",
    "itsdangerous>=2.2",
```

- [ ] **Step 2: Install into venv**

Run: `.venv/bin/pip install -e .`
Expected: install completes without errors.

- [ ] **Step 3: Verify nothing broke**

Run: `.venv/bin/pytest tests/unit/ -q`
Expected: existing tests pass (99 + previously added = ~99–110, all green).

- [ ] **Step 4: Commit**

```bash
git add pyproject.toml
git commit -m "feat: add web UI runtime dependencies"
```

### Task 0.2: Create web package skeleton

**Files:**
- Create: `src/ccguard/server/web/__init__.py` (empty)
- Create: `src/ccguard/server/web/routes.py`
- Create: `src/ccguard/server/web/templates/base.html`
- Create: `src/ccguard/server/web/templates/login.html`
- Create: `src/ccguard/server/web/static/.gitkeep`
- Modify: `src/ccguard/server/main.py`

- [ ] **Step 1: Write failing integration test**

Create `tests/integration/test_web_smoke.py`:

```python
"""Smoke test: web routes exist and serve HTML."""

from __future__ import annotations

from fastapi.testclient import TestClient

from ccguard.server.main import create_app


def test_login_page_renders() -> None:
    app = create_app()
    client = TestClient(app)
    r = client.get("/login")
    assert r.status_code == 200
    assert "text/html" in r.headers["content-type"]
    assert "ccguard" in r.text.lower()
```

- [ ] **Step 2: Run test, verify it fails**

Run: `.venv/bin/pytest tests/integration/test_web_smoke.py -v`
Expected: FAIL with 404 (route not registered).

- [ ] **Step 3: Implement minimal `web/routes.py`**

```python
"""ccguard web UI routes (Jinja2 + HTMX)."""

from __future__ import annotations

from pathlib import Path

from fastapi import APIRouter, Request
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates

_TEMPLATES_DIR = Path(__file__).parent / "templates"
templates = Jinja2Templates(directory=str(_TEMPLATES_DIR))

router = APIRouter()


@router.get("/login", response_class=HTMLResponse)
def login_form(request: Request) -> HTMLResponse:
    return templates.TemplateResponse(request, "login.html", {})
```

- [ ] **Step 4: Implement minimal `templates/base.html`**

```html
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1.0" />
    <title>{% block title %}ccguard{% endblock %}</title>
    <script src="https://unpkg.com/htmx.org@1.9.12"></script>
    <script src="https://cdn.tailwindcss.com"></script>
</head>
<body class="bg-slate-50 text-slate-900">
    {% block content %}{% endblock %}
</body>
</html>
```

- [ ] **Step 5: Implement minimal `templates/login.html`**

```html
{% extends "base.html" %}
{% block title %}ccguard — login{% endblock %}
{% block content %}
<div class="min-h-screen flex items-center justify-center">
    <form method="POST" action="/login" class="bg-white p-8 rounded-lg shadow-md w-96">
        <h1 class="text-2xl font-semibold mb-6">ccguard</h1>
        <label class="block mb-4">
            <span class="text-sm">Username</span>
            <input type="text" name="username" required
                   class="mt-1 block w-full rounded border-slate-300" />
        </label>
        <label class="block mb-4">
            <span class="text-sm">Password</span>
            <input type="password" name="password" required
                   class="mt-1 block w-full rounded border-slate-300" />
        </label>
        <button type="submit"
                class="w-full bg-slate-900 text-white rounded py-2">
            Log in
        </button>
    </form>
</div>
{% endblock %}
```

- [ ] **Step 6: Wire router in `main.py`**

In `src/ccguard/server/main.py`, find `def create_app()` and add after the existing `app.include_router(findings.router)`:

```python
    from ccguard.server.web.routes import router as web_router
    app.include_router(web_router)
```

- [ ] **Step 7: Run test, verify it passes**

Run: `.venv/bin/pytest tests/integration/test_web_smoke.py -v`
Expected: PASS.

- [ ] **Step 8: Commit**

```bash
git add src/ccguard/server/web/ src/ccguard/server/main.py tests/integration/test_web_smoke.py
git commit -m "feat(web): scaffold Jinja2 routes with login page"
```

---

## Phase 1: Auth, session, CSRF

**Goal:** Admin can log in, session cookie issued, web routes protected, API routes still use `X-CCGuard-Token`, CSRF tokens validated on POST.

### Task 1.1: AgentToken and WebSession SQL models

**Files:**
- Modify: `src/ccguard/server/db/models.py`
- Test: `tests/unit/test_db_models.py`

- [ ] **Step 1: Write failing test**

Create `tests/unit/test_db_models.py`:

```python
"""Smoke test for new SQL models."""

from __future__ import annotations

from datetime import UTC, datetime

from sqlmodel import Session, SQLModel, create_engine

from ccguard.server.db.models import AgentToken, WebSession


def test_agent_token_roundtrip() -> None:
    engine = create_engine("sqlite://")
    SQLModel.metadata.create_all(engine)
    with Session(engine) as s:
        s.add(AgentToken(label="dev", token_hash="abc", created_at=datetime.now(UTC)))
        s.commit()
        rows = list(s.exec(AgentToken.__table__.select()))  # type: ignore[attr-defined]
        assert len(rows) == 1


def test_web_session_roundtrip() -> None:
    engine = create_engine("sqlite://")
    SQLModel.metadata.create_all(engine)
    now = datetime.now(UTC)
    with Session(engine) as s:
        s.add(WebSession(id="abc123", user_id="admin", created_at=now, expires_at=now))
        s.commit()
        rows = list(s.exec(WebSession.__table__.select()))  # type: ignore[attr-defined]
        assert len(rows) == 1
```

- [ ] **Step 2: Run test, verify it fails**

Run: `.venv/bin/pytest tests/unit/test_db_models.py -v`
Expected: FAIL with `ImportError: cannot import name 'AgentToken'`.

- [ ] **Step 3: Add models**

In `src/ccguard/server/db/models.py` append:

```python
class AgentToken(SQLModel, table=True):
    """Hashed agent token. Replaces env-var list at runtime."""

    id: int | None = Field(default=None, primary_key=True)
    label: str
    token_hash: str = Field(index=True)
    created_at: datetime = Field(default_factory=_utcnow)
    last_used_at: datetime | None = None
    revoked_at: datetime | None = None


class WebSession(SQLModel, table=True):
    """Browser session for ccguard web UI."""

    id: str = Field(primary_key=True)
    user_id: str = Field(index=True)
    created_at: datetime = Field(default_factory=_utcnow)
    expires_at: datetime = Field(index=True)
```

- [ ] **Step 4: Run test, verify it passes**

Run: `.venv/bin/pytest tests/unit/test_db_models.py -v`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add src/ccguard/server/db/models.py tests/unit/test_db_models.py
git commit -m "feat(db): add AgentToken and WebSession models"
```

### Task 1.2: auth_service — password hashing and session creation

**Files:**
- Create: `src/ccguard/server/services/__init__.py` (empty)
- Create: `src/ccguard/server/services/auth_service.py`
- Test: `tests/unit/test_auth_service.py`

- [ ] **Step 1: Write failing tests**

Create `tests/unit/test_auth_service.py`:

```python
"""auth_service: password and session primitives."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

from sqlmodel import Session, SQLModel, create_engine

from ccguard.server.db.models import WebSession
from ccguard.server.services.auth_service import (
    create_session,
    hash_password,
    session_is_valid,
    verify_password,
)


def test_hash_then_verify_roundtrip() -> None:
    h = hash_password("hunter2")
    assert verify_password("hunter2", h) is True
    assert verify_password("wrong", h) is False


def test_create_session_persists_row() -> None:
    engine = create_engine("sqlite://")
    SQLModel.metadata.create_all(engine)
    with Session(engine) as s:
        sid = create_session(s, user_id="admin", ttl_hours=24)
        assert len(sid) >= 32
        row = s.get(WebSession, sid)
        assert row is not None
        assert row.user_id == "admin"
        assert row.expires_at > datetime.now(UTC)


def test_session_is_valid_expiry() -> None:
    engine = create_engine("sqlite://")
    SQLModel.metadata.create_all(engine)
    past = datetime.now(UTC) - timedelta(hours=1)
    future = datetime.now(UTC) + timedelta(hours=1)
    with Session(engine) as s:
        s.add(WebSession(id="expired", user_id="admin", created_at=past, expires_at=past))
        s.add(WebSession(id="live", user_id="admin", created_at=past, expires_at=future))
        s.commit()
        assert session_is_valid(s, "expired") is False
        assert session_is_valid(s, "live") is True
        assert session_is_valid(s, "nonexistent") is False
```

- [ ] **Step 2: Run tests, verify they fail**

Run: `.venv/bin/pytest tests/unit/test_auth_service.py -v`
Expected: FAIL (module missing).

- [ ] **Step 3: Implement `auth_service.py`**

Create `src/ccguard/server/services/auth_service.py`:

```python
"""Authentication primitives: password hashing, web sessions."""

from __future__ import annotations

import secrets
from datetime import UTC, datetime, timedelta

from passlib.context import CryptContext
from sqlmodel import Session

from ccguard.server.db.models import WebSession

_pwd_ctx = CryptContext(schemes=["bcrypt"], deprecated="auto")


def hash_password(plain: str) -> str:
    return _pwd_ctx.hash(plain)


def verify_password(plain: str, hashed: str) -> bool:
    try:
        return _pwd_ctx.verify(plain, hashed)
    except ValueError:
        return False


def create_session(session: Session, user_id: str, ttl_hours: int = 24) -> str:
    """Create a new WebSession, return its cookie value (random token)."""
    sid = secrets.token_hex(32)
    now = datetime.now(UTC)
    expires = now + timedelta(hours=ttl_hours)
    session.add(WebSession(id=sid, user_id=user_id, created_at=now, expires_at=expires))
    session.commit()
    return sid


def session_is_valid(session: Session, sid: str) -> bool:
    row = session.get(WebSession, sid)
    if row is None:
        return False
    return row.expires_at > datetime.now(UTC)


def delete_session(session: Session, sid: str) -> None:
    row = session.get(WebSession, sid)
    if row is not None:
        session.delete(row)
        session.commit()
```

- [ ] **Step 4: Run tests, verify they pass**

Run: `.venv/bin/pytest tests/unit/test_auth_service.py -v`
Expected: 3 PASS.

- [ ] **Step 5: Commit**

```bash
git add src/ccguard/server/services/ tests/unit/test_auth_service.py
git commit -m "feat(auth): password hashing and web session service"
```

### Task 1.3: CSRF token generation and verification

**Files:**
- Create: `src/ccguard/server/web/csrf.py`
- Test: `tests/unit/test_csrf.py`

- [ ] **Step 1: Write failing tests**

Create `tests/unit/test_csrf.py`:

```python
"""CSRF token: signed payload bound to session id."""

from __future__ import annotations

import pytest

from ccguard.server.web.csrf import generate_csrf_token, verify_csrf_token


def test_token_verifies_for_same_session() -> None:
    tok = generate_csrf_token(secret="s", session_id="sess1")
    assert verify_csrf_token(tok, secret="s", session_id="sess1") is True


def test_token_rejected_for_other_session() -> None:
    tok = generate_csrf_token(secret="s", session_id="sess1")
    assert verify_csrf_token(tok, secret="s", session_id="sess2") is False


def test_token_rejected_with_wrong_secret() -> None:
    tok = generate_csrf_token(secret="s", session_id="sess1")
    assert verify_csrf_token(tok, secret="other", session_id="sess1") is False


def test_malformed_token_rejected() -> None:
    assert verify_csrf_token("garbage", secret="s", session_id="sess1") is False
```

- [ ] **Step 2: Run tests, verify they fail**

Run: `.venv/bin/pytest tests/unit/test_csrf.py -v`
Expected: FAIL (module missing).

- [ ] **Step 3: Implement `csrf.py`**

Create `src/ccguard/server/web/csrf.py`:

```python
"""CSRF tokens: itsdangerous-signed strings tied to session id."""

from __future__ import annotations

from itsdangerous import BadSignature, TimestampSigner


def generate_csrf_token(*, secret: str, session_id: str) -> str:
    return TimestampSigner(secret).sign(session_id).decode()


def verify_csrf_token(token: str, *, secret: str, session_id: str, max_age_sec: int = 86400) -> bool:
    try:
        unsigned = TimestampSigner(secret).unsign(token, max_age=max_age_sec).decode()
    except (BadSignature, ValueError):
        return False
    return unsigned == session_id
```

- [ ] **Step 4: Run tests, verify they pass**

Run: `.venv/bin/pytest tests/unit/test_csrf.py -v`
Expected: 4 PASS.

- [ ] **Step 5: Commit**

```bash
git add src/ccguard/server/web/csrf.py tests/unit/test_csrf.py
git commit -m "feat(web): CSRF token primitives"
```

### Task 1.4: require_session FastAPI dependency

**Files:**
- Modify: `src/ccguard/server/web/routes.py`
- Modify: `src/ccguard/server/config.py`
- Modify: `src/ccguard/server/main.py`
- Test: `tests/integration/test_web_auth.py`

- [ ] **Step 1: Add config fields**

In `src/ccguard/server/config.py`, find the `ServerConfig` class and add:

```python
    admin_user: str = "admin"
    admin_password_hash: str | None = None  # bcrypt hash; if None, login disabled
    session_secret: str = "change-me-in-prod"
    cookie_secure: bool = False
```

In the same file, update `load()` to read from env:

```python
            admin_user=os.environ.get("CCGUARD_ADMIN_USER", "admin"),
            admin_password_hash=os.environ.get("CCGUARD_ADMIN_PASSWORD_HASH"),
            session_secret=os.environ.get("CCGUARD_SESSION_SECRET", "change-me-in-prod"),
            cookie_secure=os.environ.get("CCGUARD_COOKIE_SECURE", "false").lower() == "true",
```

- [ ] **Step 2: Write failing tests**

Create `tests/integration/test_web_auth.py`:

```python
"""Web auth: login, session cookie, separation from API tokens."""

from __future__ import annotations

import os

import pytest
from fastapi.testclient import TestClient

from ccguard.server.main import create_app
from ccguard.server.services.auth_service import hash_password


@pytest.fixture()
def admin_app(monkeypatch: pytest.MonkeyPatch) -> TestClient:
    monkeypatch.setenv("CCGUARD_ADMIN_USER", "admin")
    monkeypatch.setenv("CCGUARD_ADMIN_PASSWORD_HASH", hash_password("hunter2"))
    monkeypatch.setenv("CCGUARD_DB_URL", "sqlite://")
    monkeypatch.setenv("CCGUARD_SESSION_SECRET", "test-secret")
    return TestClient(create_app())


def test_unauthenticated_get_root_redirects_to_login(admin_app: TestClient) -> None:
    r = admin_app.get("/", follow_redirects=False)
    assert r.status_code in (302, 303, 307)
    assert "/login" in r.headers["location"]


def test_login_with_correct_password_issues_cookie(admin_app: TestClient) -> None:
    r = admin_app.post(
        "/login",
        data={"username": "admin", "password": "hunter2"},
        follow_redirects=False,
    )
    assert r.status_code in (302, 303)
    assert "ccg_session" in r.cookies


def test_login_with_wrong_password_rejected(admin_app: TestClient) -> None:
    r = admin_app.post(
        "/login",
        data={"username": "admin", "password": "wrong"},
        follow_redirects=False,
    )
    assert r.status_code == 401


def test_api_token_does_not_grant_web_access(admin_app: TestClient) -> None:
    r = admin_app.get(
        "/",
        headers={"X-CCGuard-Token": "demo"},
        follow_redirects=False,
    )
    assert r.status_code in (302, 303, 307)  # still redirected to login
```

- [ ] **Step 3: Run tests, verify they fail**

Run: `.venv/bin/pytest tests/integration/test_web_auth.py -v`
Expected: 4 FAIL.

- [ ] **Step 4: Implement auth in `web/routes.py`**

Replace the entire `src/ccguard/server/web/routes.py`:

```python
"""ccguard web UI routes (Jinja2 + HTMX)."""

from __future__ import annotations

from pathlib import Path

from fastapi import APIRouter, Depends, Form, HTTPException, Request, status
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from sqlmodel import Session

from ccguard.server.api.deps import get_session
from ccguard.server.config import ServerConfig
from ccguard.server.services.auth_service import (
    create_session,
    delete_session,
    session_is_valid,
    verify_password,
)

_TEMPLATES_DIR = Path(__file__).parent / "templates"
templates = Jinja2Templates(directory=str(_TEMPLATES_DIR))

router = APIRouter()

COOKIE_NAME = "ccg_session"


def _config(request: Request) -> ServerConfig:
    cfg: ServerConfig = request.app.state.config
    return cfg


def require_session(
    request: Request,
    session: Session = Depends(get_session),
) -> str:
    """Return user_id if cookie is valid, else raise 401 (or redirect on HTML)."""
    sid = request.cookies.get(COOKIE_NAME)
    if not sid or not session_is_valid(session, sid):
        # Redirect HTML requests, 401 JSON requests.
        accept = request.headers.get("accept", "")
        if "text/html" in accept:
            raise HTTPException(
                status_code=status.HTTP_307_TEMPORARY_REDIRECT,
                headers={"Location": "/login"},
            )
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED)
    return _config(request).admin_user  # single-user MVP


@router.get("/login", response_class=HTMLResponse)
def login_form(request: Request) -> HTMLResponse:
    return templates.TemplateResponse(request, "login.html", {})


@router.post("/login")
def login_submit(
    request: Request,
    username: str = Form(...),
    password: str = Form(...),
    session: Session = Depends(get_session),
) -> RedirectResponse:
    cfg = _config(request)
    if cfg.admin_password_hash is None:
        raise HTTPException(status_code=503, detail="admin login disabled")
    if username != cfg.admin_user or not verify_password(password, cfg.admin_password_hash):
        raise HTTPException(status_code=401, detail="invalid credentials")
    sid = create_session(session, user_id=cfg.admin_user)
    resp = RedirectResponse(url="/", status_code=303)
    resp.set_cookie(
        COOKIE_NAME,
        sid,
        httponly=True,
        samesite="lax",
        secure=cfg.cookie_secure,
        max_age=24 * 3600,
    )
    return resp


@router.post("/logout")
def logout(
    request: Request,
    session: Session = Depends(get_session),
) -> RedirectResponse:
    sid = request.cookies.get(COOKIE_NAME)
    if sid:
        delete_session(session, sid)
    resp = RedirectResponse(url="/login", status_code=303)
    resp.delete_cookie(COOKIE_NAME)
    return resp


@router.get("/", response_class=HTMLResponse)
def overview(request: Request, _user: str = Depends(require_session)) -> HTMLResponse:
    return templates.TemplateResponse(request, "overview.html", {})
```

- [ ] **Step 5: Stub `overview.html` so the import works**

Create `src/ccguard/server/web/templates/overview.html`:

```html
{% extends "base.html" %}
{% block content %}<p>Overview placeholder</p>{% endblock %}
```

- [ ] **Step 6: Run tests, verify they pass**

Run: `.venv/bin/pytest tests/integration/test_web_auth.py -v`
Expected: 4 PASS.

- [ ] **Step 7: Run full suite to check for regressions**

Run: `.venv/bin/pytest -q`
Expected: all green.

- [ ] **Step 8: Commit**

```bash
git add src/ccguard/server/web/ src/ccguard/server/config.py tests/integration/test_web_auth.py
git commit -m "feat(web): cookie session auth with admin login"
```

### Task 1.5: CSRF middleware on POST routes

**Files:**
- Modify: `src/ccguard/server/web/routes.py`
- Modify: `src/ccguard/server/web/templates/login.html` — DO NOT add CSRF here (no session yet)
- Test: extend `tests/integration/test_web_auth.py`

- [ ] **Step 1: Add CSRF test**

Append to `tests/integration/test_web_auth.py`:

```python
def test_logout_without_csrf_rejected(admin_app: TestClient) -> None:
    # First log in to get a session
    r = admin_app.post(
        "/login",
        data={"username": "admin", "password": "hunter2"},
        follow_redirects=False,
    )
    assert r.status_code == 303
    sid_cookie = r.cookies["ccg_session"]
    # Now try POST /logout without CSRF token
    r = admin_app.post(
        "/logout",
        cookies={"ccg_session": sid_cookie},
        follow_redirects=False,
    )
    assert r.status_code == 403
```

- [ ] **Step 2: Run test, verify it fails**

Run: `.venv/bin/pytest tests/integration/test_web_auth.py::test_logout_without_csrf_rejected -v`
Expected: FAIL (currently logout succeeds).

- [ ] **Step 3: Add `require_csrf` dependency**

In `src/ccguard/server/web/routes.py` add near the top after `require_session`:

```python
from ccguard.server.web.csrf import verify_csrf_token


def require_csrf(
    request: Request,
    csrf_token: str = Form(""),
) -> None:
    sid = request.cookies.get(COOKIE_NAME) or ""
    cfg = _config(request)
    if not verify_csrf_token(csrf_token, secret=cfg.session_secret, session_id=sid):
        raise HTTPException(status_code=403, detail="invalid CSRF token")
```

Update `logout` signature:

```python
@router.post("/logout")
def logout(
    request: Request,
    session: Session = Depends(get_session),
    _csrf: None = Depends(require_csrf),
) -> RedirectResponse:
    ...
```

Login POST does **not** require CSRF (no session yet to bind to).

- [ ] **Step 4: Run the test, verify it passes**

Run: `.venv/bin/pytest tests/integration/test_web_auth.py::test_logout_without_csrf_rejected -v`
Expected: PASS.

- [ ] **Step 5: Run full suite**

Run: `.venv/bin/pytest -q`
Expected: all green.

- [ ] **Step 6: Commit**

```bash
git add src/ccguard/server/web/routes.py tests/integration/test_web_auth.py
git commit -m "feat(web): CSRF protection on logout"
```

---

## Phase 2: Service layer + PolicyVersion model

**Goal:** Extract reusable business logic into `services/`, add `PolicyVersion` model + service.

### Task 2.1: PolicyVersion SQL model

**Files:**
- Modify: `src/ccguard/server/db/models.py`
- Test: `tests/unit/test_db_models.py`

- [ ] **Step 1: Append failing test**

Append to `tests/unit/test_db_models.py`:

```python
from ccguard.server.db.models import PolicyVersion


def test_policy_version_roundtrip() -> None:
    engine = create_engine("sqlite://")
    SQLModel.metadata.create_all(engine)
    with Session(engine) as s:
        s.add(
            PolicyVersion(
                revision=1,
                status="published",
                yaml_text="meta:\n  revision: 1",
                created_by="admin",
                created_at=datetime.now(UTC),
                published_at=datetime.now(UTC),
            )
        )
        s.commit()
        rows = list(s.exec(PolicyVersion.__table__.select()))  # type: ignore[attr-defined]
        assert len(rows) == 1
```

- [ ] **Step 2: Run test, verify it fails**

Run: `.venv/bin/pytest tests/unit/test_db_models.py::test_policy_version_roundtrip -v`
Expected: FAIL (`ImportError`).

- [ ] **Step 3: Add model**

In `src/ccguard/server/db/models.py` append:

```python
class PolicyVersion(SQLModel, table=True):
    """Policy revision history: draft / published / archived."""

    id: int | None = Field(default=None, primary_key=True)
    revision: int = Field(index=True)
    status: str = Field(index=True)  # "draft" | "published" | "archived"
    yaml_text: str
    comment: str | None = None
    created_by: str
    created_at: datetime = Field(default_factory=_utcnow)
    published_at: datetime | None = None
```

- [ ] **Step 4: Run test, verify it passes**

Run: `.venv/bin/pytest tests/unit/test_db_models.py -v`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add src/ccguard/server/db/models.py tests/unit/test_db_models.py
git commit -m "feat(db): add PolicyVersion model"
```

### Task 2.2: policy_service — CRUD on PolicyVersion

**Files:**
- Create: `src/ccguard/server/services/policy_service.py`
- Test: `tests/unit/test_policy_service.py`

- [ ] **Step 1: Write failing tests**

Create `tests/unit/test_policy_service.py`:

```python
"""policy_service: draft/publish/rollback/diff."""

from __future__ import annotations

from datetime import UTC, datetime

import pytest
from sqlmodel import Session, SQLModel, create_engine

from ccguard.server.db.models import PolicyVersion
from ccguard.server.services.policy_service import (
    diff_policies,
    get_current_published,
    get_draft,
    publish_draft,
    rollback_to,
    save_draft,
)


@pytest.fixture()
def db() -> Session:
    engine = create_engine("sqlite://")
    SQLModel.metadata.create_all(engine)
    return Session(engine)


_INITIAL_YAML = """\
meta:
  schema_version: 1
  revision: 1
  updated_at: '2026-01-01T00:00:00Z'
hooks:
  severity: warn
  allowlist_commands: []
  deny_unknown: true
"""

_MODIFIED_YAML = _INITIAL_YAML.replace("deny_unknown: true", "deny_unknown: false")


def test_save_draft_creates_row(db: Session) -> None:
    save_draft(db, yaml_text=_INITIAL_YAML, user_id="admin")
    draft = get_draft(db)
    assert draft is not None
    assert draft.status == "draft"


def test_save_draft_replaces_existing_draft(db: Session) -> None:
    save_draft(db, yaml_text=_INITIAL_YAML, user_id="admin")
    save_draft(db, yaml_text=_MODIFIED_YAML, user_id="admin")
    drafts = list(
        db.exec(PolicyVersion.__table__.select().where(PolicyVersion.status == "draft"))  # type: ignore[attr-defined]
    )
    assert len(drafts) == 1


def test_publish_promotes_draft_and_archives_old(db: Session) -> None:
    # Set initial published
    db.add(
        PolicyVersion(
            revision=1,
            status="published",
            yaml_text=_INITIAL_YAML,
            created_by="admin",
            created_at=datetime.now(UTC),
            published_at=datetime.now(UTC),
        )
    )
    db.commit()
    save_draft(db, yaml_text=_MODIFIED_YAML, user_id="admin")
    new_version = publish_draft(db, user_id="admin")
    assert new_version.status == "published"
    assert new_version.revision == 2
    archived = list(
        db.exec(PolicyVersion.__table__.select().where(PolicyVersion.status == "archived"))  # type: ignore[attr-defined]
    )
    assert len(archived) == 1


def test_publish_with_no_draft_raises(db: Session) -> None:
    with pytest.raises(ValueError, match="no draft"):
        publish_draft(db, user_id="admin")


def test_rollback_creates_new_draft_from_version(db: Session) -> None:
    db.add(
        PolicyVersion(
            id=42,
            revision=1,
            status="archived",
            yaml_text=_INITIAL_YAML,
            created_by="admin",
            created_at=datetime.now(UTC),
        )
    )
    db.commit()
    rollback_to(db, version_id=42, user_id="admin")
    draft = get_draft(db)
    assert draft is not None
    assert draft.yaml_text == _INITIAL_YAML


def test_get_current_published_returns_latest_revision(db: Session) -> None:
    for rev in (1, 2, 3):
        db.add(
            PolicyVersion(
                revision=rev,
                status="archived" if rev < 3 else "published",
                yaml_text=_INITIAL_YAML,
                created_by="admin",
                created_at=datetime.now(UTC),
            )
        )
    db.commit()
    current = get_current_published(db)
    assert current is not None
    assert current.revision == 3


def test_diff_policies_shows_changes() -> None:
    diff = diff_policies(_INITIAL_YAML, _MODIFIED_YAML)
    assert any("deny_unknown" in line for line in diff)
```

- [ ] **Step 2: Run tests, verify they fail**

Run: `.venv/bin/pytest tests/unit/test_policy_service.py -v`
Expected: FAIL (module missing).

- [ ] **Step 3: Implement `policy_service.py`**

Create `src/ccguard/server/services/policy_service.py`:

```python
"""Policy CRUD service: draft/publish/rollback/diff against PolicyVersion table."""

from __future__ import annotations

import difflib
from datetime import UTC, datetime

import yaml
from sqlmodel import Session, select

from ccguard.schemas import Policy
from ccguard.server.db.models import PolicyVersion


def validate_yaml(yaml_text: str) -> Policy:
    """Parse YAML and validate against Policy schema. Raises on failure."""
    data = yaml.safe_load(yaml_text)
    return Policy.model_validate(data)


def get_draft(session: Session) -> PolicyVersion | None:
    stmt = select(PolicyVersion).where(PolicyVersion.status == "draft")
    return session.exec(stmt).first()


def get_current_published(session: Session) -> PolicyVersion | None:
    stmt = (
        select(PolicyVersion)
        .where(PolicyVersion.status == "published")
        .order_by(PolicyVersion.revision.desc())  # type: ignore[attr-defined]
    )
    return session.exec(stmt).first()


def save_draft(
    session: Session,
    *,
    yaml_text: str,
    user_id: str,
    comment: str | None = None,
) -> PolicyVersion:
    """Validate and upsert the (single) draft row."""
    validate_yaml(yaml_text)  # raises if invalid
    existing = get_draft(session)
    if existing is not None:
        existing.yaml_text = yaml_text
        existing.comment = comment
        existing.created_at = datetime.now(UTC)
        existing.created_by = user_id
        session.add(existing)
        session.commit()
        session.refresh(existing)
        return existing

    current = get_current_published(session)
    next_revision = (current.revision if current else 0) + 1
    row = PolicyVersion(
        revision=next_revision,
        status="draft",
        yaml_text=yaml_text,
        comment=comment,
        created_by=user_id,
    )
    session.add(row)
    session.commit()
    session.refresh(row)
    return row


def publish_draft(session: Session, *, user_id: str) -> PolicyVersion:
    """Promote draft → published. Archive previous published."""
    draft = get_draft(session)
    if draft is None:
        raise ValueError("no draft to publish")
    validate_yaml(draft.yaml_text)
    current = get_current_published(session)
    if current is not None:
        current.status = "archived"
        session.add(current)
    draft.status = "published"
    draft.published_at = datetime.now(UTC)
    session.add(draft)
    session.commit()
    session.refresh(draft)
    return draft


def rollback_to(session: Session, *, version_id: int, user_id: str) -> PolicyVersion:
    """Copy an old version's YAML into a fresh draft."""
    src = session.get(PolicyVersion, version_id)
    if src is None:
        raise ValueError(f"version {version_id} not found")
    # Drop any existing draft, then save new one with src's content.
    existing = get_draft(session)
    if existing is not None:
        session.delete(existing)
        session.commit()
    return save_draft(
        session,
        yaml_text=src.yaml_text,
        user_id=user_id,
        comment=f"rollback to rev {src.revision}",
    )


def diff_policies(before_yaml: str, after_yaml: str) -> list[str]:
    """Unified diff (text) between two YAML policies."""
    return list(
        difflib.unified_diff(
            before_yaml.splitlines(),
            after_yaml.splitlines(),
            fromfile="published",
            tofile="draft",
            lineterm="",
        )
    )
```

- [ ] **Step 4: Run tests, verify they pass**

Run: `.venv/bin/pytest tests/unit/test_policy_service.py -v`
Expected: 7 PASS.

- [ ] **Step 5: Commit**

```bash
git add src/ccguard/server/services/policy_service.py tests/unit/test_policy_service.py
git commit -m "feat(policy): service layer with draft/publish/rollback"
```

### Task 2.3: token_service for agent tokens

**Files:**
- Create: `src/ccguard/server/services/token_service.py`
- Test: `tests/unit/test_token_service.py`

- [ ] **Step 1: Write failing tests**

Create `tests/unit/test_token_service.py`:

```python
"""token_service: CRUD on AgentToken with sha256 hashing."""

from __future__ import annotations

import pytest
from sqlmodel import Session, SQLModel, create_engine

from ccguard.server.services.token_service import (
    create_token,
    is_token_valid,
    list_tokens,
    revoke_token,
)


@pytest.fixture()
def db() -> Session:
    engine = create_engine("sqlite://")
    SQLModel.metadata.create_all(engine)
    return Session(engine)


def test_create_then_validate(db: Session) -> None:
    raw = create_token(db, label="dev")
    assert is_token_valid(db, raw) is True


def test_invalid_token_rejected(db: Session) -> None:
    create_token(db, label="dev")
    assert is_token_valid(db, "not-the-token") is False


def test_revoked_token_invalid(db: Session) -> None:
    raw = create_token(db, label="dev")
    tokens = list_tokens(db)
    revoke_token(db, tokens[0].id or 0)
    assert is_token_valid(db, raw) is False


def test_list_tokens_excludes_hash(db: Session) -> None:
    raw = create_token(db, label="dev")
    rows = list_tokens(db)
    assert len(rows) == 1
    assert raw not in rows[0].token_hash  # raw is hex sha256, won't equal raw token
```

- [ ] **Step 2: Run tests, verify they fail**

Run: `.venv/bin/pytest tests/unit/test_token_service.py -v`
Expected: FAIL (module missing).

- [ ] **Step 3: Implement `token_service.py`**

Create `src/ccguard/server/services/token_service.py`:

```python
"""Agent token CRUD with sha256-hashed storage."""

from __future__ import annotations

import hashlib
import secrets
from datetime import UTC, datetime

from sqlmodel import Session, select

from ccguard.server.db.models import AgentToken


def _hash(raw: str) -> str:
    return hashlib.sha256(raw.encode()).hexdigest()


def create_token(session: Session, *, label: str) -> str:
    """Generate a new token, store its hash, return the raw token string."""
    raw = secrets.token_urlsafe(32)
    row = AgentToken(label=label, token_hash=_hash(raw))
    session.add(row)
    session.commit()
    return raw


def list_tokens(session: Session) -> list[AgentToken]:
    return list(
        session.exec(select(AgentToken).where(AgentToken.revoked_at.is_(None)))  # type: ignore[attr-defined]
    )


def revoke_token(session: Session, token_id: int) -> None:
    row = session.get(AgentToken, token_id)
    if row is None:
        return
    row.revoked_at = datetime.now(UTC)
    session.add(row)
    session.commit()


def is_token_valid(session: Session, raw: str) -> bool:
    if not raw:
        return False
    h = _hash(raw)
    stmt = select(AgentToken).where(
        AgentToken.token_hash == h,
        AgentToken.revoked_at.is_(None),  # type: ignore[attr-defined]
    )
    row = session.exec(stmt).first()
    if row is None:
        return False
    row.last_used_at = datetime.now(UTC)
    session.add(row)
    session.commit()
    return True
```

- [ ] **Step 4: Run tests, verify they pass**

Run: `.venv/bin/pytest tests/unit/test_token_service.py -v`
Expected: 4 PASS.

- [ ] **Step 5: Commit**

```bash
git add src/ccguard/server/services/token_service.py tests/unit/test_token_service.py
git commit -m "feat(tokens): service for hashed agent token CRUD"
```

---

## Phase 3: Move PolicyLoader to DB

**Goal:** Agents read policy from DB; file becomes one-time bootstrap. Existing `/api/v1/policy` keeps working with ETag.

### Task 3.1: PolicyLoader reads from DB

**Files:**
- Modify: `src/ccguard/server/policy_loader.py`
- Test: `tests/integration/test_server_policy_etag.py` (existing — may need to seed via service)

- [ ] **Step 1: Read existing loader and ETag test to understand contract**

Run: `cat src/ccguard/server/policy_loader.py`
Run: `cat tests/integration/test_server_policy_etag.py`

Note the existing ETag format `"rev-{revision}"`.

- [ ] **Step 2: Write failing unit test for new DB-backed loader**

Create `tests/unit/test_policy_loader_db.py`:

```python
"""PolicyLoader: DB-backed, with file bootstrap on empty DB."""

from __future__ import annotations

from pathlib import Path

import pytest
from sqlmodel import Session, SQLModel, create_engine

from ccguard.server.db.models import PolicyVersion
from ccguard.server.policy_loader import PolicyLoader


_INITIAL_YAML = """\
meta:
  schema_version: 1
  revision: 1
  updated_at: '2026-01-01T00:00:00Z'
hooks:
  severity: warn
  allowlist_commands: []
  deny_unknown: true
"""


def _make_engine() -> tuple[object, Session]:
    eng = create_engine("sqlite://")
    SQLModel.metadata.create_all(eng)
    return eng, Session(eng)


def test_loader_bootstraps_from_file_when_db_empty(tmp_path: Path) -> None:
    eng, sess = _make_engine()
    f = tmp_path / "policy.yaml"
    f.write_text(_INITIAL_YAML)
    loader = PolicyLoader(file_path=f, engine=eng)
    pol, etag = loader.load_with_etag(sess)
    assert pol.meta.revision == 1
    assert etag == '"rev-1"'
    # File bootstrap created a published row.
    rows = list(sess.exec(PolicyVersion.__table__.select()))  # type: ignore[attr-defined]
    assert len(rows) == 1


def test_loader_reads_from_db_when_present(tmp_path: Path) -> None:
    eng, sess = _make_engine()
    sess.add(
        PolicyVersion(
            revision=7,
            status="published",
            yaml_text=_INITIAL_YAML.replace("revision: 1", "revision: 7"),
            created_by="admin",
        )
    )
    sess.commit()
    f = tmp_path / "policy.yaml"
    f.write_text(_INITIAL_YAML)  # different revision than DB
    loader = PolicyLoader(file_path=f, engine=eng)
    pol, etag = loader.load_with_etag(sess)
    assert pol.meta.revision == 7
    assert etag == '"rev-7"'


def test_loader_returns_none_if_no_db_and_no_file() -> None:
    eng, sess = _make_engine()
    loader = PolicyLoader(file_path=Path("/nonexistent"), engine=eng)
    with pytest.raises(FileNotFoundError):
        loader.load_with_etag(sess)
```

- [ ] **Step 3: Run tests, verify they fail**

Run: `.venv/bin/pytest tests/unit/test_policy_loader_db.py -v`
Expected: FAIL (signature mismatch).

- [ ] **Step 4: Rewrite `policy_loader.py`**

Replace `src/ccguard/server/policy_loader.py`:

```python
"""PolicyLoader: reads current policy from DB, bootstraps from YAML on empty DB."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml
from sqlmodel import Session

from ccguard.schemas import Policy
from ccguard.server.db.models import PolicyVersion
from ccguard.server.services.policy_service import get_current_published


class PolicyLoader:
    def __init__(self, *, file_path: Path, engine: Any) -> None:
        self.file_path = file_path
        self.engine = engine

    def load_with_etag(self, session: Session) -> tuple[Policy, str]:
        current = get_current_published(session)
        if current is None:
            current = self._bootstrap_from_file(session)
        policy = Policy.model_validate(yaml.safe_load(current.yaml_text))
        return policy, f'"rev-{current.revision}"'

    def _bootstrap_from_file(self, session: Session) -> PolicyVersion:
        if not self.file_path.exists():
            raise FileNotFoundError(
                f"no policy in DB and bootstrap file missing: {self.file_path}"
            )
        text = self.file_path.read_text()
        data = yaml.safe_load(text)
        revision = int(data.get("meta", {}).get("revision", 1))
        row = PolicyVersion(
            revision=revision,
            status="published",
            yaml_text=text,
            created_by="bootstrap",
        )
        session.add(row)
        session.commit()
        session.refresh(row)
        return row
```

- [ ] **Step 5: Update construction in `main.py`**

In `src/ccguard/server/main.py` find the lifespan and change:

```python
    app.state.policy_loader = PolicyLoader(Path(cfg.policy_path))
```

to:

```python
    app.state.policy_loader = PolicyLoader(file_path=Path(cfg.policy_path), engine=engine)
```

- [ ] **Step 6: Update `/api/v1/policy` handler**

Read `src/ccguard/server/api/policy.py`. Find the handler that returns the policy and update it to pass `session` to `load_with_etag()`:

```python
@router.get("/policy", response_model=None)
def get_policy(
    request: Request,
    if_none_match: str | None = Header(None),
    session: Session = Depends(get_session),
    _token: str = Depends(require_token),
) -> Response:
    loader: PolicyLoader = request.app.state.policy_loader
    policy, etag = loader.load_with_etag(session)
    if if_none_match == etag:
        return Response(status_code=304)
    return JSONResponse(policy.model_dump(), headers={"ETag": etag})
```

(Adjust imports as needed.)

- [ ] **Step 7: Run new unit tests**

Run: `.venv/bin/pytest tests/unit/test_policy_loader_db.py -v`
Expected: 3 PASS.

- [ ] **Step 8: Run existing ETag integration test**

Run: `.venv/bin/pytest tests/integration/test_server_policy_etag.py -v`
Expected: PASS.

- [ ] **Step 9: Run full suite**

Run: `.venv/bin/pytest -q`
Expected: all green.

- [ ] **Step 10: Commit**

```bash
git add src/ccguard/server/policy_loader.py src/ccguard/server/main.py src/ccguard/server/api/policy.py tests/unit/test_policy_loader_db.py
git commit -m "feat(policy): DB-backed PolicyLoader with file bootstrap"
```

---

## Phase 4: Overview page

**Goal:** Authenticated user sees fleet table with compliance status, polling every 30s.

### Task 4.1: machine_service.compliance_status

**Files:**
- Create: `src/ccguard/server/services/machine_service.py`
- Test: `tests/unit/test_machine_service.py`

- [ ] **Step 1: Write failing tests**

Create `tests/unit/test_machine_service.py`:

```python
"""machine_service: compliance_status logic."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

from ccguard.server.services.machine_service import compliance_status


def _ts(hours_ago: float) -> datetime:
    return datetime.now(UTC) - timedelta(hours=hours_ago)


def test_compliant() -> None:
    s = compliance_status(
        last_seen=_ts(0.5),
        agent_policy_revision=5,
        current_published_revision=5,
        block_findings_count=0,
    )
    assert s == "compliant"


def test_policy_old() -> None:
    s = compliance_status(
        last_seen=_ts(0.5),
        agent_policy_revision=4,
        current_published_revision=5,
        block_findings_count=0,
    )
    assert s == "policy-old"


def test_stale() -> None:
    s = compliance_status(
        last_seen=_ts(24 * 8),  # > 7 days
        agent_policy_revision=5,
        current_published_revision=5,
        block_findings_count=0,
    )
    assert s == "stale"


def test_blocking_overrides_other() -> None:
    s = compliance_status(
        last_seen=_ts(0.5),
        agent_policy_revision=5,
        current_published_revision=5,
        block_findings_count=2,
    )
    assert s == "blocking"
```

- [ ] **Step 2: Run tests, verify they fail**

Run: `.venv/bin/pytest tests/unit/test_machine_service.py -v`
Expected: FAIL (module missing).

- [ ] **Step 3: Implement**

Create `src/ccguard/server/services/machine_service.py`:

```python
"""Machine compliance status + fleet queries."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Literal

ComplianceStatus = Literal["compliant", "policy-old", "stale", "blocking"]

_STALE_THRESHOLD = timedelta(days=7)
_FRESH_THRESHOLD = timedelta(hours=24)


def compliance_status(
    *,
    last_seen: datetime,
    agent_policy_revision: int | None,
    current_published_revision: int,
    block_findings_count: int,
) -> ComplianceStatus:
    if block_findings_count > 0:
        return "blocking"
    age = datetime.now(UTC) - last_seen
    if age > _STALE_THRESHOLD:
        return "stale"
    if agent_policy_revision is None or agent_policy_revision < current_published_revision:
        return "policy-old"
    return "compliant"
```

- [ ] **Step 4: Run tests, verify they pass**

Run: `.venv/bin/pytest tests/unit/test_machine_service.py -v`
Expected: 4 PASS.

- [ ] **Step 5: Commit**

```bash
git add src/ccguard/server/services/machine_service.py tests/unit/test_machine_service.py
git commit -m "feat(machines): compliance_status service function"
```

### Task 4.2: fleet listing query (with snapshot's policy rev)

**Files:**
- Modify: `src/ccguard/server/services/machine_service.py`
- Test: extend `tests/unit/test_machine_service.py`

- [ ] **Step 1: Write failing test**

Append to `tests/unit/test_machine_service.py`:

```python
import json

import pytest
from sqlmodel import Session, SQLModel, create_engine

from ccguard.server.db.models import (
    FindingRecord,
    InventorySnapshot,
    Machine,
    PolicyVersion,
)
from ccguard.server.services.machine_service import list_machines_with_status


@pytest.fixture()
def db_with_fleet() -> Session:
    engine = create_engine("sqlite://")
    SQLModel.metadata.create_all(engine)
    s = Session(engine)
    s.add(
        PolicyVersion(
            revision=5,
            status="published",
            yaml_text="meta:\n  revision: 5",
            created_by="admin",
        )
    )
    now = datetime.now(UTC)
    s.add(
        Machine(
            machine_id="m1", machine_label="laptop-tim",
            first_seen=now, last_seen=now, agent_version="0.1.0",
        )
    )
    s.add(
        InventorySnapshot(
            machine_id="m1",
            received_at=now,
            payload_json=json.dumps({"schema_version": 1, "meta": {"revision": 5}}),
        )
    )
    s.commit()
    return s


def test_list_machines_returns_one_compliant(db_with_fleet: Session) -> None:
    rows = list_machines_with_status(db_with_fleet)
    assert len(rows) == 1
    assert rows[0].machine_id == "m1"
    assert rows[0].status == "compliant"
```

- [ ] **Step 2: Run test, verify it fails**

Run: `.venv/bin/pytest tests/unit/test_machine_service.py::test_list_machines_returns_one_compliant -v`
Expected: FAIL.

- [ ] **Step 3: Implement listing**

Append to `src/ccguard/server/services/machine_service.py`:

```python
import json
from dataclasses import dataclass

from sqlmodel import Session, select

from ccguard.server.db.models import FindingRecord, InventorySnapshot, Machine
from ccguard.server.services.policy_service import get_current_published


@dataclass
class MachineRow:
    machine_id: str
    machine_label: str | None
    last_seen: datetime
    agent_version: str | None
    agent_policy_revision: int | None
    warn_count: int
    block_count: int
    status: ComplianceStatus


def list_machines_with_status(session: Session) -> list[MachineRow]:
    current = get_current_published(session)
    current_rev = current.revision if current else 0

    machines = list(session.exec(select(Machine)))
    out: list[MachineRow] = []
    for m in machines:
        # Latest inventory for this machine.
        latest_inv = session.exec(
            select(InventorySnapshot)
            .where(InventorySnapshot.machine_id == m.machine_id)
            .order_by(InventorySnapshot.received_at.desc())  # type: ignore[attr-defined]
        ).first()
        agent_rev: int | None = None
        if latest_inv is not None:
            try:
                data = json.loads(latest_inv.payload_json)
                agent_rev = int(data.get("meta", {}).get("revision", 0)) or None
            except (ValueError, KeyError):
                agent_rev = None

        # Counts of findings linked to the latest snapshot.
        warn_count = 0
        block_count = 0
        if latest_inv is not None and latest_inv.id is not None:
            findings = list(
                session.exec(
                    select(FindingRecord).where(FindingRecord.inventory_id == latest_inv.id)
                )
            )
            for f in findings:
                if f.severity == "warn":
                    warn_count += 1
                elif f.severity == "block":
                    block_count += 1

        out.append(
            MachineRow(
                machine_id=m.machine_id,
                machine_label=m.machine_label,
                last_seen=m.last_seen,
                agent_version=m.agent_version,
                agent_policy_revision=agent_rev,
                warn_count=warn_count,
                block_count=block_count,
                status=compliance_status(
                    last_seen=m.last_seen,
                    agent_policy_revision=agent_rev,
                    current_published_revision=current_rev,
                    block_findings_count=block_count,
                ),
            )
        )
    return out
```

- [ ] **Step 4: Run tests, verify they pass**

Run: `.venv/bin/pytest tests/unit/test_machine_service.py -v`
Expected: all PASS.

- [ ] **Step 5: Commit**

```bash
git add src/ccguard/server/services/machine_service.py tests/unit/test_machine_service.py
git commit -m "feat(machines): list_machines_with_status with compliance"
```

### Task 4.3: Overview template + route

**Files:**
- Modify: `src/ccguard/server/web/templates/base.html` (add sidebar)
- Modify: `src/ccguard/server/web/templates/overview.html`
- Create: `src/ccguard/server/web/templates/components/_fleet_table.html`
- Modify: `src/ccguard/server/web/routes.py`
- Test: extend `tests/integration/test_web_smoke.py`

- [ ] **Step 1: Write failing test**

Append to `tests/integration/test_web_smoke.py`:

```python
def test_overview_renders_fleet_table(monkeypatch: pytest.MonkeyPatch) -> None:
    import json
    from datetime import UTC, datetime
    from ccguard.server.db.models import InventorySnapshot, Machine, PolicyVersion
    from ccguard.server.services.auth_service import create_session, hash_password
    from sqlmodel import Session

    monkeypatch.setenv("CCGUARD_ADMIN_PASSWORD_HASH", hash_password("hunter2"))
    monkeypatch.setenv("CCGUARD_DB_URL", "sqlite://")
    monkeypatch.setenv("CCGUARD_SESSION_SECRET", "test-secret")

    app = create_app()
    client = TestClient(app)
    engine = app.state.engine
    now = datetime.now(UTC)
    with Session(engine) as s:
        s.add(
            PolicyVersion(
                revision=1, status="published",
                yaml_text="meta:\n  revision: 1", created_by="admin",
            )
        )
        s.add(
            Machine(
                machine_id="m1", machine_label="laptop",
                first_seen=now, last_seen=now, agent_version="0.1.0",
            )
        )
        s.add(
            InventorySnapshot(
                machine_id="m1", received_at=now,
                payload_json=json.dumps({"meta": {"revision": 1}}),
            )
        )
        sid = create_session(s, user_id="admin")

    r = client.get("/", cookies={"ccg_session": sid})
    assert r.status_code == 200
    assert "laptop" in r.text
    assert "compliant" in r.text.lower()
```

Add import at the top of the file: `import pytest`.

- [ ] **Step 2: Run test, verify it fails**

Run: `.venv/bin/pytest tests/integration/test_web_smoke.py::test_overview_renders_fleet_table -v`
Expected: FAIL (template doesn't render fleet).

- [ ] **Step 3: Update `base.html` with sidebar layout**

Replace `src/ccguard/server/web/templates/base.html`:

```html
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1.0" />
    <title>{% block title %}ccguard{% endblock %}</title>
    <script src="https://unpkg.com/htmx.org@1.9.12"></script>
    <script src="https://cdn.tailwindcss.com"></script>
</head>
<body class="bg-slate-50 text-slate-900 min-h-screen">
    {% if user %}
    <div class="flex min-h-screen">
        <aside class="w-56 bg-slate-900 text-slate-100 p-4">
            <h1 class="text-xl font-bold mb-6">ccguard</h1>
            <nav class="space-y-2 text-sm">
                <a href="/" class="block hover:bg-slate-800 px-3 py-2 rounded">Overview</a>
                <a href="/machines" class="block hover:bg-slate-800 px-3 py-2 rounded">Machines</a>
                <a href="/findings" class="block hover:bg-slate-800 px-3 py-2 rounded">Findings</a>
                <a href="/policy" class="block hover:bg-slate-800 px-3 py-2 rounded">Policy</a>
                <a href="/policy/history" class="block hover:bg-slate-800 px-3 py-2 rounded">History</a>
                <a href="/settings" class="block hover:bg-slate-800 px-3 py-2 rounded">Settings</a>
            </nav>
            <form method="POST" action="/logout" class="mt-6">
                <input type="hidden" name="csrf_token" value="{{ csrf_token }}" />
                <button class="text-sm text-slate-400 hover:text-white">Log out</button>
            </form>
        </aside>
        <main class="flex-1 p-8">{% block content %}{% endblock %}</main>
    </div>
    {% else %}
    {% block content_anonymous %}{{ self.content() }}{% endblock %}
    {% endif %}
</body>
</html>
```

- [ ] **Step 4: Update `overview.html`**

Replace `src/ccguard/server/web/templates/overview.html`:

```html
{% extends "base.html" %}
{% block title %}ccguard — overview{% endblock %}
{% block content %}
<h2 class="text-2xl font-semibold mb-6">Overview</h2>
<div class="bg-white rounded-lg shadow p-4"
     hx-get="/_partials/overview/fleet-table"
     hx-trigger="every 30s">
    {% include "components/_fleet_table.html" %}
</div>
{% endblock %}
```

- [ ] **Step 5: Create fleet table partial**

Create `src/ccguard/server/web/templates/components/_fleet_table.html`:

```html
<table class="w-full text-sm">
    <thead>
        <tr class="text-left text-slate-500 border-b">
            <th class="py-2">Host</th>
            <th>Agent</th>
            <th>Last seen</th>
            <th>Policy rev</th>
            <th>Warn / Block</th>
            <th>Status</th>
        </tr>
    </thead>
    <tbody>
        {% for m in machines %}
        <tr class="border-b last:border-0">
            <td class="py-2">
                <a href="/machines/{{ m.machine_id }}" class="hover:underline">
                    {{ m.machine_label or m.machine_id[:12] }}
                </a>
            </td>
            <td>{{ m.agent_version or "-" }}</td>
            <td>{{ m.last_seen.isoformat(timespec="minutes") }}</td>
            <td>{{ m.agent_policy_revision or "-" }}</td>
            <td>{{ m.warn_count }} / {{ m.block_count }}</td>
            <td>
                {% if m.status == "compliant" %}<span class="text-emerald-600">● compliant</span>
                {% elif m.status == "policy-old" %}<span class="text-amber-600">◎ policy old</span>
                {% elif m.status == "stale" %}<span class="text-slate-400">○ stale</span>
                {% elif m.status == "blocking" %}<span class="text-red-600">■ blocking</span>
                {% endif %}
            </td>
        </tr>
        {% else %}
        <tr><td colspan="6" class="py-6 text-center text-slate-400">No machines yet.</td></tr>
        {% endfor %}
    </tbody>
</table>
```

- [ ] **Step 6: Wire `/` and partial routes**

Replace the existing `overview` handler in `src/ccguard/server/web/routes.py` with:

```python
@router.get("/", response_class=HTMLResponse)
def overview_page(
    request: Request,
    user: str = Depends(require_session),
    session: Session = Depends(get_session),
) -> HTMLResponse:
    from ccguard.server.services.machine_service import list_machines_with_status
    machines = list_machines_with_status(session)
    return templates.TemplateResponse(
        request,
        "overview.html",
        {
            "user": user,
            "machines": machines,
            "csrf_token": _csrf_for(request),
        },
    )


@router.get("/_partials/overview/fleet-table", response_class=HTMLResponse)
def overview_fleet_partial(
    request: Request,
    _user: str = Depends(require_session),
    session: Session = Depends(get_session),
) -> HTMLResponse:
    from ccguard.server.services.machine_service import list_machines_with_status
    machines = list_machines_with_status(session)
    return templates.TemplateResponse(
        request,
        "components/_fleet_table.html",
        {"machines": machines},
    )
```

Add helper near the top of the file:

```python
from ccguard.server.web.csrf import generate_csrf_token, verify_csrf_token


def _csrf_for(request: Request) -> str:
    sid = request.cookies.get(COOKIE_NAME) or ""
    return generate_csrf_token(secret=_config(request).session_secret, session_id=sid)
```

- [ ] **Step 7: Run test, verify it passes**

Run: `.venv/bin/pytest tests/integration/test_web_smoke.py::test_overview_renders_fleet_table -v`
Expected: PASS.

- [ ] **Step 8: Run full suite**

Run: `.venv/bin/pytest -q`
Expected: all green.

- [ ] **Step 9: Commit**

```bash
git add src/ccguard/server/web/ tests/integration/test_web_smoke.py
git commit -m "feat(web): overview page with fleet table and HTMX polling"
```

---

## Phase 5: Machines list + detail

**Goal:** `/machines` shows all machines (same data as Overview, fuller view). `/machines/{id}` shows inventory tabs, findings tab, history tab. Revoke button works.

### Task 5.1: Machines list page

**Files:**
- Create: `src/ccguard/server/web/templates/machines_list.html`
- Modify: `src/ccguard/server/web/routes.py`
- Test: extend `tests/integration/test_web_smoke.py`

- [ ] **Step 1: Write failing test**

Append to `tests/integration/test_web_smoke.py`:

```python
def test_machines_list_renders(monkeypatch: pytest.MonkeyPatch) -> None:
    from datetime import UTC, datetime
    from ccguard.server.db.models import Machine
    from ccguard.server.services.auth_service import create_session, hash_password
    from sqlmodel import Session

    monkeypatch.setenv("CCGUARD_ADMIN_PASSWORD_HASH", hash_password("h"))
    monkeypatch.setenv("CCGUARD_DB_URL", "sqlite://")
    app = create_app()
    client = TestClient(app)
    with Session(app.state.engine) as s:
        s.add(
            Machine(
                machine_id="m1", machine_label="laptop",
                first_seen=datetime.now(UTC), last_seen=datetime.now(UTC),
                agent_version="0.1.0",
            )
        )
        sid = create_session(s, user_id="admin")
    r = client.get("/machines", cookies={"ccg_session": sid})
    assert r.status_code == 200
    assert "laptop" in r.text
```

- [ ] **Step 2: Run test, verify it fails**

Run: `.venv/bin/pytest tests/integration/test_web_smoke.py::test_machines_list_renders -v`
Expected: FAIL (route missing).

- [ ] **Step 3: Add template**

Create `src/ccguard/server/web/templates/machines_list.html`:

```html
{% extends "base.html" %}
{% block title %}ccguard — machines{% endblock %}
{% block content %}
<h2 class="text-2xl font-semibold mb-6">Machines ({{ machines|length }})</h2>
<div class="bg-white rounded-lg shadow p-4">
    {% include "components/_fleet_table.html" %}
</div>
{% endblock %}
```

- [ ] **Step 4: Add route**

In `src/ccguard/server/web/routes.py` append:

```python
@router.get("/machines", response_class=HTMLResponse)
def machines_list(
    request: Request,
    user: str = Depends(require_session),
    session: Session = Depends(get_session),
) -> HTMLResponse:
    from ccguard.server.services.machine_service import list_machines_with_status
    machines = list_machines_with_status(session)
    return templates.TemplateResponse(
        request,
        "machines_list.html",
        {"user": user, "machines": machines, "csrf_token": _csrf_for(request)},
    )
```

- [ ] **Step 5: Run test, verify it passes**

Run: `.venv/bin/pytest tests/integration/test_web_smoke.py::test_machines_list_renders -v`
Expected: PASS.

- [ ] **Step 6: Commit**

```bash
git add src/ccguard/server/web/ tests/integration/test_web_smoke.py
git commit -m "feat(web): machines list page"
```

### Task 5.2: Machine detail page (inventory + findings tabs)

**Files:**
- Create: `src/ccguard/server/web/templates/machine_detail.html`
- Modify: `src/ccguard/server/services/machine_service.py` (add `get_inventory_for`)
- Modify: `src/ccguard/server/web/routes.py`
- Test: extend `tests/integration/test_web_smoke.py`

- [ ] **Step 1: Write failing test**

Append to `tests/integration/test_web_smoke.py`:

```python
def test_machine_detail_renders_inventory(monkeypatch: pytest.MonkeyPatch) -> None:
    import json
    from datetime import UTC, datetime
    from ccguard.server.db.models import InventorySnapshot, Machine
    from ccguard.server.services.auth_service import create_session, hash_password
    from sqlmodel import Session

    monkeypatch.setenv("CCGUARD_ADMIN_PASSWORD_HASH", hash_password("h"))
    monkeypatch.setenv("CCGUARD_DB_URL", "sqlite://")
    app = create_app()
    client = TestClient(app)
    with Session(app.state.engine) as s:
        now = datetime.now(UTC)
        s.add(
            Machine(machine_id="m1", machine_label="laptop",
                    first_seen=now, last_seen=now, agent_version="0.1.0")
        )
        s.add(
            InventorySnapshot(
                machine_id="m1", received_at=now,
                payload_json=json.dumps({"mcp_servers": [{"name": "fs"}]}),
            )
        )
        sid = create_session(s, user_id="admin")
    r = client.get("/machines/m1", cookies={"ccg_session": sid})
    assert r.status_code == 200
    assert "laptop" in r.text
    assert "fs" in r.text  # MCP server name from inventory
```

- [ ] **Step 2: Run test, verify it fails**

Run: `.venv/bin/pytest tests/integration/test_web_smoke.py::test_machine_detail_renders_inventory -v`
Expected: FAIL.

- [ ] **Step 3: Add service function**

Append to `src/ccguard/server/services/machine_service.py`:

```python
def get_latest_inventory_json(session: Session, machine_id: str) -> dict[str, object] | None:
    inv = session.exec(
        select(InventorySnapshot)
        .where(InventorySnapshot.machine_id == machine_id)
        .order_by(InventorySnapshot.received_at.desc())  # type: ignore[attr-defined]
    ).first()
    if inv is None:
        return None
    try:
        return json.loads(inv.payload_json)
    except ValueError:
        return None


def get_findings_for_machine(
    session: Session, machine_id: str, limit: int = 200
) -> list[FindingRecord]:
    return list(
        session.exec(
            select(FindingRecord)
            .where(FindingRecord.machine_id == machine_id)
            .order_by(FindingRecord.discovered_at.desc())  # type: ignore[attr-defined]
            .limit(limit)
        )
    )
```

- [ ] **Step 4: Add template**

Create `src/ccguard/server/web/templates/machine_detail.html`:

```html
{% extends "base.html" %}
{% block title %}ccguard — {{ machine.machine_label or machine.machine_id }}{% endblock %}
{% block content %}
<h2 class="text-2xl font-semibold mb-2">{{ machine.machine_label or machine.machine_id }}</h2>
<p class="text-slate-500 text-sm mb-6">{{ machine.machine_id }} · {{ machine.agent_version or "-" }} · last seen {{ machine.last_seen.isoformat(timespec="minutes") }}</p>

<div class="grid grid-cols-2 gap-6">
    <section class="bg-white rounded-lg shadow p-4">
        <h3 class="font-semibold mb-3">Inventory</h3>
        {% if inventory %}
            {% for section_name, items in inventory.items() %}
                {% if items is sequence and items|length > 0 and items[0] is mapping %}
                <details class="border-b py-2">
                    <summary class="cursor-pointer">{{ section_name }} ({{ items|length }})</summary>
                    <ul class="ml-4 mt-2 text-sm space-y-1">
                        {% for item in items %}
                        <li>{{ item.get("name") or item.get("event") or item.get("path") or "-" }}</li>
                        {% endfor %}
                    </ul>
                </details>
                {% endif %}
            {% endfor %}
        {% else %}
            <p class="text-slate-400 text-sm">No inventory yet.</p>
        {% endif %}
    </section>

    <section class="bg-white rounded-lg shadow p-4">
        <h3 class="font-semibold mb-3">Findings ({{ findings|length }})</h3>
        <ul class="text-sm space-y-2">
            {% for f in findings %}
            <li class="border-b pb-2">
                <span class="font-mono text-xs uppercase
                    {% if f.severity == 'block' %}text-red-600
                    {% elif f.severity == 'warn' %}text-amber-600
                    {% else %}text-slate-500{% endif %}">
                    {{ f.severity }}
                </span>
                {{ f.rule_id }}
            </li>
            {% else %}
            <li class="text-slate-400">No findings.</li>
            {% endfor %}
        </ul>
    </section>
</div>

<form method="POST" action="/machines/{{ machine.machine_id }}/revoke" class="mt-6">
    <input type="hidden" name="csrf_token" value="{{ csrf_token }}" />
    <button class="text-sm text-red-600 hover:underline"
            onclick="return confirm('Revoke this machine?')">Revoke machine</button>
</form>
{% endblock %}
```

- [ ] **Step 5: Add route**

In `src/ccguard/server/web/routes.py` append:

```python
@router.get("/machines/{machine_id}", response_class=HTMLResponse)
def machine_detail(
    request: Request,
    machine_id: str,
    user: str = Depends(require_session),
    session: Session = Depends(get_session),
) -> HTMLResponse:
    from ccguard.server.db.models import Machine
    from ccguard.server.services.machine_service import (
        get_findings_for_machine,
        get_latest_inventory_json,
    )
    machine = session.get(Machine, machine_id)
    if machine is None:
        raise HTTPException(status_code=404)
    return templates.TemplateResponse(
        request,
        "machine_detail.html",
        {
            "user": user,
            "machine": machine,
            "inventory": get_latest_inventory_json(session, machine_id),
            "findings": get_findings_for_machine(session, machine_id),
            "csrf_token": _csrf_for(request),
        },
    )
```

- [ ] **Step 6: Run test, verify it passes**

Run: `.venv/bin/pytest tests/integration/test_web_smoke.py::test_machine_detail_renders_inventory -v`
Expected: PASS.

- [ ] **Step 7: Commit**

```bash
git add src/ccguard/server/web/ src/ccguard/server/services/machine_service.py tests/integration/test_web_smoke.py
git commit -m "feat(web): machine detail with inventory and findings"
```

### Task 5.3: Revoke machine

**Files:**
- Modify: `src/ccguard/server/web/routes.py`
- Test: extend `tests/integration/test_web_smoke.py`

- [ ] **Step 1: Write failing test**

Append to `tests/integration/test_web_smoke.py`:

```python
def test_revoke_machine_deletes_row(monkeypatch: pytest.MonkeyPatch) -> None:
    from datetime import UTC, datetime
    from ccguard.server.db.models import Machine
    from ccguard.server.services.auth_service import create_session, hash_password
    from ccguard.server.web.csrf import generate_csrf_token
    from sqlmodel import Session

    monkeypatch.setenv("CCGUARD_ADMIN_PASSWORD_HASH", hash_password("h"))
    monkeypatch.setenv("CCGUARD_DB_URL", "sqlite://")
    monkeypatch.setenv("CCGUARD_SESSION_SECRET", "s")
    app = create_app()
    client = TestClient(app)
    with Session(app.state.engine) as s:
        s.add(
            Machine(machine_id="m1", machine_label="x",
                    first_seen=datetime.now(UTC), last_seen=datetime.now(UTC),
                    agent_version="0.1.0")
        )
        sid = create_session(s, user_id="admin")
    csrf = generate_csrf_token(secret="s", session_id=sid)
    r = client.post(
        "/machines/m1/revoke",
        data={"csrf_token": csrf},
        cookies={"ccg_session": sid},
        follow_redirects=False,
    )
    assert r.status_code == 303
    with Session(app.state.engine) as s:
        assert s.get(Machine, "m1") is None
```

- [ ] **Step 2: Run test, verify it fails**

Run: `.venv/bin/pytest tests/integration/test_web_smoke.py::test_revoke_machine_deletes_row -v`
Expected: FAIL.

- [ ] **Step 3: Add route**

In `src/ccguard/server/web/routes.py` append:

```python
@router.post("/machines/{machine_id}/revoke")
def revoke_machine(
    request: Request,
    machine_id: str,
    _user: str = Depends(require_session),
    _csrf: None = Depends(require_csrf),
    session: Session = Depends(get_session),
) -> RedirectResponse:
    from ccguard.server.db.models import Machine
    row = session.get(Machine, machine_id)
    if row is not None:
        session.delete(row)
        session.commit()
    return RedirectResponse(url="/machines", status_code=303)
```

- [ ] **Step 4: Run test, verify it passes**

Run: `.venv/bin/pytest tests/integration/test_web_smoke.py::test_revoke_machine_deletes_row -v`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add src/ccguard/server/web/routes.py tests/integration/test_web_smoke.py
git commit -m "feat(web): revoke machine via POST"
```

---

## Phase 6: Findings feed

**Goal:** Global findings list with severity/rule_id/machine_id filters and lazy pagination.

### Task 6.1: finding_service query

**Files:**
- Create: `src/ccguard/server/services/finding_service.py`
- Test: `tests/unit/test_finding_service.py`

- [ ] **Step 1: Write failing test**

Create `tests/unit/test_finding_service.py`:

```python
"""finding_service: filtered query."""

from __future__ import annotations

from datetime import UTC, datetime

import pytest
from sqlmodel import Session, SQLModel, create_engine

from ccguard.server.db.models import FindingRecord
from ccguard.server.services.finding_service import query_findings


@pytest.fixture()
def db() -> Session:
    eng = create_engine("sqlite://")
    SQLModel.metadata.create_all(eng)
    s = Session(eng)
    for i, (sev, rid, mid) in enumerate(
        [
            ("warn", "mcp.denylist", "m1"),
            ("warn", "agents.forbidden_tool", "m1"),
            ("block", "permissions.dangerously_skip", "m2"),
        ]
    ):
        s.add(
            FindingRecord(
                machine_id=mid, inventory_id=i,
                rule_id=rid, severity=sev,
                discovered_at=datetime.now(UTC),
                payload_json="{}",
            )
        )
    s.commit()
    return s


def test_query_no_filters_returns_all(db: Session) -> None:
    rows = query_findings(db, limit=10)
    assert len(rows) == 3


def test_query_filter_by_severity(db: Session) -> None:
    rows = query_findings(db, severity="block", limit=10)
    assert len(rows) == 1
    assert rows[0].severity == "block"


def test_query_filter_by_rule_id(db: Session) -> None:
    rows = query_findings(db, rule_id="agents.forbidden_tool", limit=10)
    assert len(rows) == 1


def test_query_filter_by_machine(db: Session) -> None:
    rows = query_findings(db, machine_id="m1", limit=10)
    assert len(rows) == 2


def test_query_respects_limit(db: Session) -> None:
    rows = query_findings(db, limit=2)
    assert len(rows) == 2
```

- [ ] **Step 2: Run tests, verify they fail**

Run: `.venv/bin/pytest tests/unit/test_finding_service.py -v`
Expected: FAIL.

- [ ] **Step 3: Implement**

Create `src/ccguard/server/services/finding_service.py`:

```python
"""Finding queries with filters and pagination."""

from __future__ import annotations

from sqlmodel import Session, select

from ccguard.server.db.models import FindingRecord


def query_findings(
    session: Session,
    *,
    severity: str | None = None,
    rule_id: str | None = None,
    machine_id: str | None = None,
    limit: int = 50,
) -> list[FindingRecord]:
    stmt = select(FindingRecord)
    if severity:
        stmt = stmt.where(FindingRecord.severity == severity)
    if rule_id:
        stmt = stmt.where(FindingRecord.rule_id == rule_id)
    if machine_id:
        stmt = stmt.where(FindingRecord.machine_id == machine_id)
    stmt = stmt.order_by(FindingRecord.discovered_at.desc()).limit(limit)  # type: ignore[attr-defined]
    return list(session.exec(stmt))
```

- [ ] **Step 4: Run tests, verify they pass**

Run: `.venv/bin/pytest tests/unit/test_finding_service.py -v`
Expected: 5 PASS.

- [ ] **Step 5: Commit**

```bash
git add src/ccguard/server/services/finding_service.py tests/unit/test_finding_service.py
git commit -m "feat(findings): service with severity/rule_id/machine_id filters"
```

### Task 6.2: Findings feed page

**Files:**
- Create: `src/ccguard/server/web/templates/findings_feed.html`
- Modify: `src/ccguard/server/web/routes.py`
- Test: extend `tests/integration/test_web_smoke.py`

- [ ] **Step 1: Write failing test**

Append to `tests/integration/test_web_smoke.py`:

```python
def test_findings_feed_renders_with_filter(monkeypatch: pytest.MonkeyPatch) -> None:
    from datetime import UTC, datetime
    from ccguard.server.db.models import FindingRecord
    from ccguard.server.services.auth_service import create_session, hash_password
    from sqlmodel import Session

    monkeypatch.setenv("CCGUARD_ADMIN_PASSWORD_HASH", hash_password("h"))
    monkeypatch.setenv("CCGUARD_DB_URL", "sqlite://")
    app = create_app()
    client = TestClient(app)
    with Session(app.state.engine) as s:
        s.add(
            FindingRecord(
                machine_id="m1", inventory_id=1,
                rule_id="agents.forbidden_tool", severity="warn",
                discovered_at=datetime.now(UTC), payload_json="{}",
            )
        )
        sid = create_session(s, user_id="admin")
    r = client.get(
        "/findings?rule_id=agents.forbidden_tool",
        cookies={"ccg_session": sid},
    )
    assert r.status_code == 200
    assert "agents.forbidden_tool" in r.text
```

- [ ] **Step 2: Run test, verify it fails**

Run: `.venv/bin/pytest tests/integration/test_web_smoke.py::test_findings_feed_renders_with_filter -v`
Expected: FAIL.

- [ ] **Step 3: Add template**

Create `src/ccguard/server/web/templates/findings_feed.html`:

```html
{% extends "base.html" %}
{% block title %}ccguard — findings{% endblock %}
{% block content %}
<h2 class="text-2xl font-semibold mb-6">Findings</h2>
<form method="GET" action="/findings" class="bg-white rounded-lg shadow p-4 mb-4 flex gap-4">
    <select name="severity" class="rounded border-slate-300 text-sm">
        <option value="">all severities</option>
        <option value="block" {% if filters.severity == "block" %}selected{% endif %}>block</option>
        <option value="warn"  {% if filters.severity == "warn"  %}selected{% endif %}>warn</option>
        <option value="info"  {% if filters.severity == "info"  %}selected{% endif %}>info</option>
    </select>
    <input type="text" name="rule_id" placeholder="rule_id"
           value="{{ filters.rule_id or '' }}" class="rounded border-slate-300 text-sm" />
    <input type="text" name="machine_id" placeholder="machine_id"
           value="{{ filters.machine_id or '' }}" class="rounded border-slate-300 text-sm" />
    <button class="bg-slate-900 text-white text-sm rounded px-4">Filter</button>
</form>

<div class="bg-white rounded-lg shadow p-4">
    <table class="w-full text-sm">
        <thead><tr class="text-left text-slate-500 border-b">
            <th>When</th><th>Machine</th><th>Rule</th><th>Severity</th>
        </tr></thead>
        <tbody>
        {% for f in findings %}
        <tr class="border-b last:border-0">
            <td class="py-2">{{ f.discovered_at.isoformat(timespec="seconds") }}</td>
            <td>
                <a href="/machines/{{ f.machine_id }}" class="hover:underline">
                    {{ f.machine_id[:12] }}
                </a>
            </td>
            <td class="font-mono">{{ f.rule_id }}</td>
            <td class="{% if f.severity == 'block' %}text-red-600
                       {% elif f.severity == 'warn' %}text-amber-600
                       {% else %}text-slate-500{% endif %}">{{ f.severity }}</td>
        </tr>
        {% else %}
        <tr><td colspan="4" class="py-6 text-center text-slate-400">No findings.</td></tr>
        {% endfor %}
        </tbody>
    </table>
</div>
{% endblock %}
```

- [ ] **Step 4: Add route**

In `src/ccguard/server/web/routes.py` append:

```python
@router.get("/findings", response_class=HTMLResponse)
def findings_page(
    request: Request,
    severity: str | None = None,
    rule_id: str | None = None,
    machine_id: str | None = None,
    user: str = Depends(require_session),
    session: Session = Depends(get_session),
) -> HTMLResponse:
    from ccguard.server.services.finding_service import query_findings
    findings = query_findings(
        session, severity=severity, rule_id=rule_id, machine_id=machine_id, limit=200,
    )
    return templates.TemplateResponse(
        request,
        "findings_feed.html",
        {
            "user": user,
            "findings": findings,
            "filters": {"severity": severity, "rule_id": rule_id, "machine_id": machine_id},
            "csrf_token": _csrf_for(request),
        },
    )
```

- [ ] **Step 5: Run test, verify it passes**

Run: `.venv/bin/pytest tests/integration/test_web_smoke.py::test_findings_feed_renders_with_filter -v`
Expected: PASS.

- [ ] **Step 6: Commit**

```bash
git add src/ccguard/server/web/ tests/integration/test_web_smoke.py
git commit -m "feat(web): findings feed with severity/rule_id/machine_id filters"
```

---

## Phase 7: Policy editor (form-only)

**Goal:** Admin edits each policy section through forms, saves as draft, sees diff against published, then publishes.

This is the most complex phase. Split into form scaffolding (7.1), per-section editors (7.2), save-and-publish actions (7.3).

### Task 7.1: Policy editor scaffold

**Files:**
- Create: `src/ccguard/server/web/templates/policy_editor.html`
- Create: `src/ccguard/server/web/templates/components/_policy_section_mcp.html`
- Create: `src/ccguard/server/web/templates/components/_policy_section_hooks.html`
- Modify: `src/ccguard/server/web/routes.py`
- Test: extend `tests/integration/test_web_smoke.py`

- [ ] **Step 1: Write failing test**

Append to `tests/integration/test_web_smoke.py`:

```python
def test_policy_editor_renders_current_policy(monkeypatch: pytest.MonkeyPatch) -> None:
    from ccguard.server.db.models import PolicyVersion
    from ccguard.server.services.auth_service import create_session, hash_password
    from sqlmodel import Session

    monkeypatch.setenv("CCGUARD_ADMIN_PASSWORD_HASH", hash_password("h"))
    monkeypatch.setenv("CCGUARD_DB_URL", "sqlite://")
    app = create_app()
    client = TestClient(app)
    with Session(app.state.engine) as s:
        s.add(
            PolicyVersion(
                revision=1, status="published",
                yaml_text=(
                    "meta:\n  schema_version: 1\n  revision: 1\n  updated_at: '2026-01-01T00:00:00Z'\n"
                    "mcp_servers:\n  severity: warn\n  allowlist_names: [filesystem]\n"
                ),
                created_by="admin",
            )
        )
        sid = create_session(s, user_id="admin")
    r = client.get("/policy", cookies={"ccg_session": sid})
    assert r.status_code == 200
    assert "filesystem" in r.text  # current allowlist appears in form
```

- [ ] **Step 2: Run test, verify it fails**

Run: `.venv/bin/pytest tests/integration/test_web_smoke.py::test_policy_editor_renders_current_policy -v`
Expected: FAIL.

- [ ] **Step 3: Add scaffold template**

Create `src/ccguard/server/web/templates/policy_editor.html`:

```html
{% extends "base.html" %}
{% block title %}ccguard — policy{% endblock %}
{% block content %}
<h2 class="text-2xl font-semibold mb-2">Policy editor</h2>
<p class="text-slate-500 text-sm mb-6">
    Current rev <span class="font-mono">{{ current_rev }}</span> ·
    Draft rev <span class="font-mono">{{ draft_rev }}</span>
    {% if has_draft %}<span class="text-amber-600">· unsaved</span>{% endif %}
</p>

<form method="POST" action="/policy/draft" class="space-y-4">
    <input type="hidden" name="csrf_token" value="{{ csrf_token }}" />

    {% include "components/_policy_section_mcp.html" %}
    {% include "components/_policy_section_hooks.html" %}

    <div class="flex gap-2 sticky bottom-0 bg-slate-50 py-4">
        <button type="submit"
                class="bg-slate-900 text-white rounded px-4 py-2">Save draft</button>
        <button type="submit" formaction="/policy/publish"
                class="bg-emerald-700 text-white rounded px-4 py-2"
                onclick="return confirm('Publish draft to all agents?')">Publish</button>
    </div>
</form>

{% if diff_lines %}
<section class="bg-white rounded-lg shadow p-4 mt-6">
    <h3 class="font-semibold mb-3">Diff vs published</h3>
    <pre class="text-xs overflow-x-auto">{% for line in diff_lines %}{{ line }}
{% endfor %}</pre>
</section>
{% endif %}
{% endblock %}
```

- [ ] **Step 4: Add section partials**

Create `src/ccguard/server/web/templates/components/_policy_section_mcp.html`:

```html
<details open class="bg-white rounded-lg shadow p-4">
    <summary class="cursor-pointer font-semibold">MCP servers</summary>
    <div class="mt-4 space-y-3 text-sm">
        <label class="block">
            severity:
            <select name="mcp_servers.severity" class="rounded border-slate-300 ml-2">
                <option value="info"  {% if policy.mcp_servers.severity == 'info'  %}selected{% endif %}>info</option>
                <option value="warn"  {% if policy.mcp_servers.severity == 'warn'  %}selected{% endif %}>warn</option>
                <option value="block" {% if policy.mcp_servers.severity == 'block' %}selected{% endif %}>block</option>
            </select>
        </label>
        <label class="block">
            allowlist_names (comma-separated):
            <input type="text" name="mcp_servers.allowlist_names"
                   value="{{ policy.mcp_servers.allowlist_names | join(', ') }}"
                   class="mt-1 block w-full rounded border-slate-300" />
        </label>
        <label class="block">
            denylist_names (comma-separated):
            <input type="text" name="mcp_servers.denylist_names"
                   value="{{ policy.mcp_servers.denylist_names | join(', ') }}"
                   class="mt-1 block w-full rounded border-slate-300" />
        </label>
        <label class="block">
            denylist_url_patterns (comma-separated):
            <input type="text" name="mcp_servers.denylist_url_patterns"
                   value="{{ policy.mcp_servers.denylist_url_patterns | join(', ') }}"
                   class="mt-1 block w-full rounded border-slate-300" />
        </label>
        <label class="inline-flex items-center">
            <input type="checkbox" name="mcp_servers.deny_all_unknown" value="1"
                   {% if policy.mcp_servers.deny_all_unknown %}checked{% endif %} />
            <span class="ml-2">deny all unknown</span>
        </label>
    </div>
</details>
```

Create `src/ccguard/server/web/templates/components/_policy_section_hooks.html`:

```html
<details class="bg-white rounded-lg shadow p-4">
    <summary class="cursor-pointer font-semibold">Hooks</summary>
    <div class="mt-4 space-y-3 text-sm">
        <label class="block">
            severity:
            <select name="hooks.severity" class="rounded border-slate-300 ml-2">
                <option value="info"  {% if policy.hooks.severity == 'info'  %}selected{% endif %}>info</option>
                <option value="warn"  {% if policy.hooks.severity == 'warn'  %}selected{% endif %}>warn</option>
                <option value="block" {% if policy.hooks.severity == 'block' %}selected{% endif %}>block</option>
            </select>
        </label>
        <label class="block">
            allowlist_commands (newline-separated):
            <textarea name="hooks.allowlist_commands" rows="4"
                      class="mt-1 block w-full rounded border-slate-300 font-mono text-xs"
                      >{{ policy.hooks.allowlist_commands | join('\n') }}</textarea>
        </label>
        <label class="inline-flex items-center">
            <input type="checkbox" name="hooks.deny_unknown" value="1"
                   {% if policy.hooks.deny_unknown %}checked{% endif %} />
            <span class="ml-2">deny unknown</span>
        </label>
    </div>
</details>
```

(Sections for `network`, `commands`, `skills`, `agents`, `env` follow the same pattern — add them iteratively, but Task 7.2 will cover the rest. For now the scaffold has 2 sections so we can prove the round-trip.)

- [ ] **Step 5: Add `/policy` route**

In `src/ccguard/server/web/routes.py` append:

```python
@router.get("/policy", response_class=HTMLResponse)
def policy_editor(
    request: Request,
    user: str = Depends(require_session),
    session: Session = Depends(get_session),
) -> HTMLResponse:
    from ccguard.server.services.policy_service import (
        diff_policies,
        get_current_published,
        get_draft,
        validate_yaml,
    )
    current = get_current_published(session)
    draft = get_draft(session)
    source = draft if draft is not None else current
    if source is None:
        raise HTTPException(status_code=503, detail="no policy in DB (run bootstrap first)")
    policy_obj = validate_yaml(source.yaml_text)
    diff_lines = (
        diff_policies(current.yaml_text, draft.yaml_text)
        if current is not None and draft is not None
        else []
    )
    return templates.TemplateResponse(
        request,
        "policy_editor.html",
        {
            "user": user,
            "policy": policy_obj,
            "current_rev": current.revision if current else "-",
            "draft_rev": draft.revision if draft else (current.revision + 1 if current else 1),
            "has_draft": draft is not None,
            "diff_lines": diff_lines,
            "csrf_token": _csrf_for(request),
        },
    )
```

- [ ] **Step 6: Run test, verify it passes**

Run: `.venv/bin/pytest tests/integration/test_web_smoke.py::test_policy_editor_renders_current_policy -v`
Expected: PASS.

- [ ] **Step 7: Commit**

```bash
git add src/ccguard/server/web/ tests/integration/test_web_smoke.py
git commit -m "feat(policy): editor scaffold with MCP and Hooks sections"
```

### Task 7.2: Remaining policy sections

**Files:**
- Create: `_policy_section_network.html`, `_policy_section_commands.html`, `_policy_section_skills.html`, `_policy_section_agents.html`, `_policy_section_env.html`
- Modify: `policy_editor.html` to include all of them
- Test: extend smoke test to check all sections present

- [ ] **Step 1: Write failing test**

Append to `tests/integration/test_web_smoke.py`:

```python
def test_policy_editor_has_all_sections(monkeypatch: pytest.MonkeyPatch) -> None:
    from ccguard.server.db.models import PolicyVersion
    from ccguard.server.services.auth_service import create_session, hash_password
    from sqlmodel import Session

    monkeypatch.setenv("CCGUARD_ADMIN_PASSWORD_HASH", hash_password("h"))
    monkeypatch.setenv("CCGUARD_DB_URL", "sqlite://")
    app = create_app()
    client = TestClient(app)
    yaml_text = (
        "meta:\n  schema_version: 1\n  revision: 1\n  updated_at: '2026-01-01T00:00:00Z'\n"
    )
    with Session(app.state.engine) as s:
        s.add(PolicyVersion(revision=1, status="published",
                            yaml_text=yaml_text, created_by="admin"))
        sid = create_session(s, user_id="admin")
    r = client.get("/policy", cookies={"ccg_session": sid})
    for needle in ["MCP servers", "Network", "Commands", "Skills", "Hooks", "Agents", "Env"]:
        assert needle in r.text, f"missing section: {needle}"
```

- [ ] **Step 2: Run test, verify it fails**

Run: `.venv/bin/pytest tests/integration/test_web_smoke.py::test_policy_editor_has_all_sections -v`
Expected: FAIL.

- [ ] **Step 3: Create remaining section partials**

All five partials follow the exact pattern of `_policy_section_mcp.html`. Form field names use dot notation `<section>.<field>`. Use comma-separated `<input type="text">` for short lists; newline-separated `<textarea rows="4">` for regex/hash lists.

Create `_policy_section_network.html`:

```html
<details class="bg-white rounded-lg shadow p-4">
    <summary class="cursor-pointer font-semibold">Network</summary>
    <div class="mt-4 space-y-3 text-sm">
        <label class="block">severity:
            <select name="network.severity" class="rounded border-slate-300 ml-2">
                <option value="info"  {% if policy.network.severity == 'info'  %}selected{% endif %}>info</option>
                <option value="warn"  {% if policy.network.severity == 'warn'  %}selected{% endif %}>warn</option>
                <option value="block" {% if policy.network.severity == 'block' %}selected{% endif %}>block</option>
            </select>
        </label>
        <label class="block">allowlist_hosts (comma-separated):
            <input type="text" name="network.allowlist_hosts"
                   value="{{ policy.network.allowlist_hosts | join(', ') }}"
                   class="mt-1 block w-full rounded border-slate-300" /></label>
        <label class="block">denylist_hosts (comma-separated):
            <input type="text" name="network.denylist_hosts"
                   value="{{ policy.network.denylist_hosts | join(', ') }}"
                   class="mt-1 block w-full rounded border-slate-300" /></label>
        <label class="inline-flex items-center">
            <input type="checkbox" name="network.deny_all_unknown" value="1"
                   {% if policy.network.deny_all_unknown %}checked{% endif %} />
            <span class="ml-2">deny all unknown</span></label>
    </div>
</details>
```

Create `_policy_section_commands.html`:

```html
<details class="bg-white rounded-lg shadow p-4">
    <summary class="cursor-pointer font-semibold">Commands</summary>
    <div class="mt-4 space-y-3 text-sm">
        <label class="block">severity:
            <select name="commands.severity" class="rounded border-slate-300 ml-2">
                <option value="info"  {% if policy.commands.severity == 'info'  %}selected{% endif %}>info</option>
                <option value="warn"  {% if policy.commands.severity == 'warn'  %}selected{% endif %}>warn</option>
                <option value="block" {% if policy.commands.severity == 'block' %}selected{% endif %}>block</option>
            </select>
        </label>
        <label class="block">denylist_patterns (one regex per line):
            <textarea name="commands.denylist_patterns" rows="4"
                      class="mt-1 block w-full rounded border-slate-300 font-mono text-xs"
                      >{{ policy.commands.denylist_patterns | join('\n') }}</textarea></label>
        <label class="block">allowlist_patterns (one regex per line):
            <textarea name="commands.allowlist_patterns" rows="4"
                      class="mt-1 block w-full rounded border-slate-300 font-mono text-xs"
                      >{{ policy.commands.allowlist_patterns | join('\n') }}</textarea></label>
        <p class="text-xs text-slate-400">always_deny is hardcoded in schema and not editable.</p>
    </div>
</details>
```

Create `_policy_section_skills.html`:

```html
<details class="bg-white rounded-lg shadow p-4">
    <summary class="cursor-pointer font-semibold">Skills</summary>
    <div class="mt-4 space-y-3 text-sm">
        <label class="block">severity:
            <select name="skills.severity" class="rounded border-slate-300 ml-2">
                <option value="info"  {% if policy.skills.severity == 'info'  %}selected{% endif %}>info</option>
                <option value="warn"  {% if policy.skills.severity == 'warn'  %}selected{% endif %}>warn</option>
                <option value="block" {% if policy.skills.severity == 'block' %}selected{% endif %}>block</option>
            </select>
        </label>
        <label class="block">allowlist_names (comma-separated):
            <input type="text" name="skills.allowlist_names"
                   value="{{ policy.skills.allowlist_names | join(', ') }}"
                   class="mt-1 block w-full rounded border-slate-300" /></label>
        <label class="block">trusted_dir_hashes (one sha256 per line):
            <textarea name="skills.trusted_dir_hashes" rows="4"
                      class="mt-1 block w-full rounded border-slate-300 font-mono text-xs"
                      >{{ policy.skills.trusted_dir_hashes | join('\n') }}</textarea></label>
        <label class="inline-flex items-center">
            <input type="checkbox" name="skills.deny_all_unknown" value="1"
                   {% if policy.skills.deny_all_unknown %}checked{% endif %} />
            <span class="ml-2">deny all unknown</span></label>
    </div>
</details>
```

Create `_policy_section_agents.html`:

```html
<details class="bg-white rounded-lg shadow p-4">
    <summary class="cursor-pointer font-semibold">Agents</summary>
    <div class="mt-4 space-y-3 text-sm">
        <label class="block">severity:
            <select name="agents.severity" class="rounded border-slate-300 ml-2">
                <option value="info"  {% if policy.agents.severity == 'info'  %}selected{% endif %}>info</option>
                <option value="warn"  {% if policy.agents.severity == 'warn'  %}selected{% endif %}>warn</option>
                <option value="block" {% if policy.agents.severity == 'block' %}selected{% endif %}>block</option>
            </select>
        </label>
        <label class="block">allowlist_names (comma-separated):
            <input type="text" name="agents.allowlist_names"
                   value="{{ policy.agents.allowlist_names | join(', ') }}"
                   class="mt-1 block w-full rounded border-slate-300" /></label>
        <label class="block">denylist_names (comma-separated):
            <input type="text" name="agents.denylist_names"
                   value="{{ policy.agents.denylist_names | join(', ') }}"
                   class="mt-1 block w-full rounded border-slate-300" /></label>
        <label class="block">denylist_tools (comma-separated, e.g. Bash, Write, Edit):
            <input type="text" name="agents.denylist_tools"
                   value="{{ policy.agents.denylist_tools | join(', ') }}"
                   class="mt-1 block w-full rounded border-slate-300" /></label>
        <label class="block">trusted_file_hashes (one sha256 per line):
            <textarea name="agents.trusted_file_hashes" rows="4"
                      class="mt-1 block w-full rounded border-slate-300 font-mono text-xs"
                      >{{ policy.agents.trusted_file_hashes | join('\n') }}</textarea></label>
        <label class="inline-flex items-center">
            <input type="checkbox" name="agents.deny_all_unknown" value="1"
                   {% if policy.agents.deny_all_unknown %}checked{% endif %} />
            <span class="ml-2">deny all unknown</span></label>
    </div>
</details>
```

Create `_policy_section_env.html`:

```html
<details class="bg-white rounded-lg shadow p-4">
    <summary class="cursor-pointer font-semibold">Env</summary>
    <div class="mt-4 space-y-3 text-sm">
        <label class="block">severity:
            <select name="env.severity" class="rounded border-slate-300 ml-2">
                <option value="info"  {% if policy.env.severity == 'info'  %}selected{% endif %}>info</option>
                <option value="warn"  {% if policy.env.severity == 'warn'  %}selected{% endif %}>warn</option>
                <option value="block" {% if policy.env.severity == 'block' %}selected{% endif %}>block</option>
            </select>
        </label>
        <label class="block">denylist_patterns (one regex per line):
            <textarea name="env.denylist_patterns" rows="4"
                      class="mt-1 block w-full rounded border-slate-300 font-mono text-xs"
                      >{{ policy.env.denylist_patterns | join('\n') }}</textarea></label>
        <label class="block">allowlist_names (comma-separated):
            <input type="text" name="env.allowlist_names"
                   value="{{ policy.env.allowlist_names | join(', ') }}"
                   class="mt-1 block w-full rounded border-slate-300" /></label>
    </div>
</details>
```

- [ ] **Step 4: Update `policy_editor.html` to include all 7 sections**

In `policy_editor.html`, add includes after the existing two:

```html
    {% include "components/_policy_section_mcp.html" %}
    {% include "components/_policy_section_network.html" %}
    {% include "components/_policy_section_commands.html" %}
    {% include "components/_policy_section_skills.html" %}
    {% include "components/_policy_section_hooks.html" %}
    {% include "components/_policy_section_agents.html" %}
    {% include "components/_policy_section_env.html" %}
```

- [ ] **Step 5: Run test, verify it passes**

Run: `.venv/bin/pytest tests/integration/test_web_smoke.py::test_policy_editor_has_all_sections -v`
Expected: PASS.

- [ ] **Step 6: Commit**

```bash
git add src/ccguard/server/web/templates/
git commit -m "feat(policy): all 7 policy sections in editor"
```

### Task 7.3: Save draft and publish

**Files:**
- Create: `src/ccguard/server/web/policy_form.py` (form → YAML serializer)
- Modify: `src/ccguard/server/web/routes.py`
- Test: `tests/unit/test_policy_form.py`, extend smoke tests

- [ ] **Step 1: Write failing form-serializer test**

Create `tests/unit/test_policy_form.py`:

```python
"""policy_form: serialize Starlette form data → Policy YAML."""

from __future__ import annotations

from ccguard.server.web.policy_form import form_to_yaml


def test_simple_form_roundtrip() -> None:
    form = {
        "mcp_servers.severity": "warn",
        "mcp_servers.allowlist_names": "filesystem, memory",
        "mcp_servers.denylist_names": "",
        "mcp_servers.denylist_url_patterns": "http://*",
        "mcp_servers.deny_all_unknown": "",  # unchecked
        "hooks.severity": "warn",
        "hooks.allowlist_commands": "/opt/ccguard-enforce\n/root/.ccguard/bin/enforce",
        "hooks.deny_unknown": "1",
    }
    yaml_text = form_to_yaml(form, current_revision=1)
    assert "filesystem" in yaml_text
    assert "memory" in yaml_text
    assert "deny_all_unknown: false" in yaml_text
    assert "deny_unknown: true" in yaml_text
    assert "revision: 2" in yaml_text  # bumped


def test_empty_lists_become_empty_arrays() -> None:
    form = {
        "mcp_servers.severity": "warn",
        "mcp_servers.allowlist_names": "",
        "mcp_servers.denylist_names": "",
        "mcp_servers.denylist_url_patterns": "",
        "hooks.severity": "warn",
        "hooks.allowlist_commands": "",
        "hooks.deny_unknown": "1",
    }
    yaml_text = form_to_yaml(form, current_revision=4)
    assert "revision: 5" in yaml_text
```

- [ ] **Step 2: Run tests, verify they fail**

Run: `.venv/bin/pytest tests/unit/test_policy_form.py -v`
Expected: FAIL.

- [ ] **Step 3: Implement `policy_form.py`**

Create `src/ccguard/server/web/policy_form.py`:

```python
"""Convert browser form data → Policy YAML text (validated against schema)."""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any, Mapping

import yaml

from ccguard.schemas import Policy


def _csv_to_list(raw: str) -> list[str]:
    return [s.strip() for s in raw.split(",") if s.strip()]


def _lines_to_list(raw: str) -> list[str]:
    return [s.strip() for s in raw.splitlines() if s.strip()]


def _checkbox(raw: str) -> bool:
    return raw == "1"


def _section(form: Mapping[str, str], prefix: str, fields: dict[str, str]) -> dict[str, Any]:
    """Build a dict for one policy section.

    `fields` is {form_field: kind}, kind ∈ {"csv", "lines", "bool", "str"}.
    """
    out: dict[str, Any] = {}
    for field, kind in fields.items():
        raw = form.get(f"{prefix}.{field}", "")
        if kind == "csv":
            out[field] = _csv_to_list(raw)
        elif kind == "lines":
            out[field] = _lines_to_list(raw)
        elif kind == "bool":
            out[field] = _checkbox(raw)
        else:
            out[field] = raw
    return out


_SECTIONS: dict[str, dict[str, str]] = {
    "mcp_servers": {
        "severity": "str",
        "allowlist_names": "csv",
        "denylist_names": "csv",
        "denylist_url_patterns": "csv",
        "deny_all_unknown": "bool",
    },
    "network": {
        "severity": "str",
        "allowlist_hosts": "csv",
        "denylist_hosts": "csv",
        "deny_all_unknown": "bool",
    },
    "commands": {
        "severity": "str",
        "denylist_patterns": "lines",
        "allowlist_patterns": "lines",
    },
    "skills": {
        "severity": "str",
        "allowlist_names": "csv",
        "trusted_dir_hashes": "lines",
        "deny_all_unknown": "bool",
    },
    "hooks": {
        "severity": "str",
        "allowlist_commands": "lines",
        "deny_unknown": "bool",
    },
    "agents": {
        "severity": "str",
        "allowlist_names": "csv",
        "denylist_names": "csv",
        "denylist_tools": "csv",
        "trusted_file_hashes": "lines",
        "deny_all_unknown": "bool",
    },
    "env": {
        "severity": "str",
        "denylist_patterns": "lines",
        "allowlist_names": "csv",
    },
}


def form_to_yaml(form: Mapping[str, str], *, current_revision: int) -> str:
    data: dict[str, Any] = {
        "meta": {
            "schema_version": 1,
            "revision": current_revision + 1,
            "updated_at": datetime.now(UTC).isoformat().replace("+00:00", "Z"),
        },
    }
    for section, fields in _SECTIONS.items():
        data[section] = _section(form, section, fields)
    # Validate by round-tripping through Policy.
    Policy.model_validate(data)
    return yaml.safe_dump(data, sort_keys=False)
```

- [ ] **Step 4: Run tests, verify they pass**

Run: `.venv/bin/pytest tests/unit/test_policy_form.py -v`
Expected: PASS.

- [ ] **Step 5: Add `/policy/draft` and `/policy/publish` routes**

In `src/ccguard/server/web/routes.py` append:

```python
@router.post("/policy/draft")
async def save_policy_draft(
    request: Request,
    user: str = Depends(require_session),
    _csrf: None = Depends(require_csrf),
    session: Session = Depends(get_session),
) -> RedirectResponse:
    from ccguard.server.services.policy_service import (
        get_current_published,
        save_draft,
    )
    from ccguard.server.web.policy_form import form_to_yaml

    form = await request.form()
    current = get_current_published(session)
    current_rev = current.revision if current else 0
    yaml_text = form_to_yaml(dict(form), current_revision=current_rev)
    save_draft(session, yaml_text=yaml_text, user_id=user)
    return RedirectResponse(url="/policy", status_code=303)


@router.post("/policy/publish")
async def publish_policy(
    request: Request,
    user: str = Depends(require_session),
    _csrf: None = Depends(require_csrf),
    session: Session = Depends(get_session),
) -> RedirectResponse:
    # If form contained edits, save the draft first.
    from ccguard.server.services.policy_service import (
        get_current_published,
        get_draft,
        publish_draft,
        save_draft,
    )
    from ccguard.server.web.policy_form import form_to_yaml

    form = await request.form()
    if any(k.startswith(prefix + ".") for k in form.keys() for prefix in (
        "mcp_servers", "network", "commands", "skills", "hooks", "agents", "env",
    )):
        current = get_current_published(session)
        current_rev = current.revision if current else 0
        save_draft(
            session,
            yaml_text=form_to_yaml(dict(form), current_revision=current_rev),
            user_id=user,
        )
    if get_draft(session) is None:
        raise HTTPException(status_code=400, detail="no draft to publish")
    publish_draft(session, user_id=user)
    return RedirectResponse(url="/policy", status_code=303)
```

- [ ] **Step 6: Write integration test**

Append to `tests/integration/test_web_smoke.py`:

```python
def test_save_draft_then_publish_bumps_revision(monkeypatch: pytest.MonkeyPatch) -> None:
    from ccguard.server.db.models import PolicyVersion
    from ccguard.server.services.auth_service import create_session, hash_password
    from ccguard.server.web.csrf import generate_csrf_token
    from sqlmodel import Session

    monkeypatch.setenv("CCGUARD_ADMIN_PASSWORD_HASH", hash_password("h"))
    monkeypatch.setenv("CCGUARD_DB_URL", "sqlite://")
    monkeypatch.setenv("CCGUARD_SESSION_SECRET", "s")
    app = create_app()
    client = TestClient(app)
    with Session(app.state.engine) as s:
        s.add(PolicyVersion(
            revision=1, status="published",
            yaml_text=(
                "meta:\n  schema_version: 1\n  revision: 1\n  updated_at: '2026-01-01T00:00:00Z'\n"
            ),
            created_by="admin",
        ))
        sid = create_session(s, user_id="admin")
    csrf = generate_csrf_token(secret="s", session_id=sid)

    form_data = {
        "csrf_token": csrf,
        "mcp_servers.severity": "warn",
        "mcp_servers.allowlist_names": "filesystem",
        "mcp_servers.denylist_names": "",
        "mcp_servers.denylist_url_patterns": "",
        "network.severity": "warn",
        "network.allowlist_hosts": "",
        "network.denylist_hosts": "",
        "commands.severity": "warn",
        "commands.denylist_patterns": "",
        "commands.allowlist_patterns": "",
        "skills.severity": "warn",
        "skills.allowlist_names": "",
        "skills.trusted_dir_hashes": "",
        "hooks.severity": "warn",
        "hooks.allowlist_commands": "",
        "hooks.deny_unknown": "1",
        "agents.severity": "warn",
        "agents.allowlist_names": "",
        "agents.denylist_names": "",
        "agents.denylist_tools": "Bash",
        "agents.trusted_file_hashes": "",
        "env.severity": "warn",
        "env.denylist_patterns": "",
        "env.allowlist_names": "",
    }
    r = client.post("/policy/publish", data=form_data,
                    cookies={"ccg_session": sid}, follow_redirects=False)
    assert r.status_code == 303
    with Session(app.state.engine) as s:
        rows = list(s.exec(PolicyVersion.__table__.select()  # type: ignore[attr-defined]
                           .where(PolicyVersion.status == "published")))
        assert any(r.revision == 2 for r in rows)
```

- [ ] **Step 7: Run test, verify it passes**

Run: `.venv/bin/pytest tests/integration/test_web_smoke.py::test_save_draft_then_publish_bumps_revision -v`
Expected: PASS.

- [ ] **Step 8: Run full suite**

Run: `.venv/bin/pytest -q`
Expected: all green.

- [ ] **Step 9: Commit**

```bash
git add src/ccguard/server/web/ tests/unit/test_policy_form.py tests/integration/test_web_smoke.py
git commit -m "feat(policy): save draft and publish through web form"
```

---

## Phase 8: Policy history + rollback

**Goal:** `/policy/history` lists all versions with view/diff/rollback actions.

### Task 8.1: History page and rollback action

**Files:**
- Create: `src/ccguard/server/web/templates/policy_history.html`
- Modify: `src/ccguard/server/web/routes.py`
- Test: extend `tests/integration/test_web_smoke.py`

- [ ] **Step 1: Write failing test**

Append to `tests/integration/test_web_smoke.py`:

```python
def test_policy_history_rollback(monkeypatch: pytest.MonkeyPatch) -> None:
    from ccguard.server.db.models import PolicyVersion
    from ccguard.server.services.auth_service import create_session, hash_password
    from ccguard.server.services.policy_service import get_draft
    from ccguard.server.web.csrf import generate_csrf_token
    from sqlmodel import Session

    monkeypatch.setenv("CCGUARD_ADMIN_PASSWORD_HASH", hash_password("h"))
    monkeypatch.setenv("CCGUARD_DB_URL", "sqlite://")
    monkeypatch.setenv("CCGUARD_SESSION_SECRET", "s")
    app = create_app()
    client = TestClient(app)
    yaml_text = "meta:\n  schema_version: 1\n  revision: 1\n  updated_at: '2026-01-01T00:00:00Z'\n"
    with Session(app.state.engine) as s:
        s.add(PolicyVersion(id=1, revision=1, status="archived",
                            yaml_text=yaml_text, created_by="admin"))
        s.add(PolicyVersion(revision=2, status="published",
                            yaml_text=yaml_text, created_by="admin"))
        sid = create_session(s, user_id="admin")
    csrf = generate_csrf_token(secret="s", session_id=sid)

    r = client.get("/policy/history", cookies={"ccg_session": sid})
    assert r.status_code == 200
    assert "rev 1" in r.text or "1" in r.text

    r = client.post(
        "/policy/rollback/1",
        data={"csrf_token": csrf},
        cookies={"ccg_session": sid},
        follow_redirects=False,
    )
    assert r.status_code == 303
    with Session(app.state.engine) as s:
        assert get_draft(s) is not None
```

- [ ] **Step 2: Run test, verify it fails**

Run: `.venv/bin/pytest tests/integration/test_web_smoke.py::test_policy_history_rollback -v`
Expected: FAIL.

- [ ] **Step 3: Add template**

Create `src/ccguard/server/web/templates/policy_history.html`:

```html
{% extends "base.html" %}
{% block title %}ccguard — policy history{% endblock %}
{% block content %}
<h2 class="text-2xl font-semibold mb-6">Policy history</h2>
<div class="bg-white rounded-lg shadow p-4">
    <table class="w-full text-sm">
        <thead><tr class="text-left text-slate-500 border-b">
            <th class="py-2">Rev</th><th>Status</th><th>Created</th><th>By</th><th>Comment</th><th></th>
        </tr></thead>
        <tbody>
        {% for v in versions %}
        <tr class="border-b last:border-0">
            <td class="py-2 font-mono">{{ v.revision }}</td>
            <td>{{ v.status }}</td>
            <td>{{ v.created_at.isoformat(timespec="minutes") }}</td>
            <td>{{ v.created_by }}</td>
            <td>{{ v.comment or "-" }}</td>
            <td>
                {% if v.status != "draft" %}
                <form method="POST" action="/policy/rollback/{{ v.id }}" class="inline">
                    <input type="hidden" name="csrf_token" value="{{ csrf_token }}" />
                    <button class="text-blue-600 hover:underline"
                            onclick="return confirm('Create draft from rev {{ v.revision }}?')">
                        rollback to this
                    </button>
                </form>
                {% endif %}
            </td>
        </tr>
        {% endfor %}
        </tbody>
    </table>
</div>
{% endblock %}
```

- [ ] **Step 4: Add routes**

In `src/ccguard/server/web/routes.py` append:

```python
@router.get("/policy/history", response_class=HTMLResponse)
def policy_history(
    request: Request,
    user: str = Depends(require_session),
    session: Session = Depends(get_session),
) -> HTMLResponse:
    from ccguard.server.db.models import PolicyVersion
    versions = list(
        session.exec(
            select(PolicyVersion).order_by(PolicyVersion.revision.desc())  # type: ignore[attr-defined]
        )
    )
    return templates.TemplateResponse(
        request,
        "policy_history.html",
        {"user": user, "versions": versions, "csrf_token": _csrf_for(request)},
    )


@router.post("/policy/rollback/{version_id}")
def policy_rollback(
    request: Request,
    version_id: int,
    user: str = Depends(require_session),
    _csrf: None = Depends(require_csrf),
    session: Session = Depends(get_session),
) -> RedirectResponse:
    from ccguard.server.services.policy_service import rollback_to
    rollback_to(session, version_id=version_id, user_id=user)
    return RedirectResponse(url="/policy", status_code=303)
```

Make sure `select` is imported at the top:

```python
from sqlmodel import Session, select
```

- [ ] **Step 5: Run test, verify it passes**

Run: `.venv/bin/pytest tests/integration/test_web_smoke.py::test_policy_history_rollback -v`
Expected: PASS.

- [ ] **Step 6: Commit**

```bash
git add src/ccguard/server/web/ tests/integration/test_web_smoke.py
git commit -m "feat(policy): version history with rollback"
```

---

## Phase 9: Settings (token CRUD, password change)

**Goal:** Admin can create/revoke agent tokens and change own password.

### Task 9.1: Token CRUD page

**Files:**
- Create: `src/ccguard/server/web/templates/settings.html`
- Modify: `src/ccguard/server/web/routes.py`
- Test: extend `tests/integration/test_web_smoke.py`

- [ ] **Step 1: Write failing test**

Append to `tests/integration/test_web_smoke.py`:

```python
def test_settings_create_and_revoke_token(monkeypatch: pytest.MonkeyPatch) -> None:
    from ccguard.server.db.models import AgentToken
    from ccguard.server.services.auth_service import create_session, hash_password
    from ccguard.server.web.csrf import generate_csrf_token
    from sqlmodel import Session

    monkeypatch.setenv("CCGUARD_ADMIN_PASSWORD_HASH", hash_password("h"))
    monkeypatch.setenv("CCGUARD_DB_URL", "sqlite://")
    monkeypatch.setenv("CCGUARD_SESSION_SECRET", "s")
    app = create_app()
    client = TestClient(app)
    with Session(app.state.engine) as s:
        sid = create_session(s, user_id="admin")
    csrf = generate_csrf_token(secret="s", session_id=sid)

    # Create
    r = client.post(
        "/settings/tokens",
        data={"csrf_token": csrf, "label": "dev"},
        cookies={"ccg_session": sid},
        follow_redirects=False,
    )
    assert r.status_code == 303
    with Session(app.state.engine) as s:
        tokens = list(s.exec(AgentToken.__table__.select()))  # type: ignore[attr-defined]
        assert len(tokens) == 1
        token_id = tokens[0].id

    # Revoke
    r = client.post(
        f"/settings/tokens/{token_id}/revoke",
        data={"csrf_token": csrf},
        cookies={"ccg_session": sid},
        follow_redirects=False,
    )
    assert r.status_code == 303
    with Session(app.state.engine) as s:
        token = s.get(AgentToken, token_id)
        assert token is not None
        assert token.revoked_at is not None
```

- [ ] **Step 2: Run test, verify it fails**

Run: `.venv/bin/pytest tests/integration/test_web_smoke.py::test_settings_create_and_revoke_token -v`
Expected: FAIL.

- [ ] **Step 3: Add template**

Create `src/ccguard/server/web/templates/settings.html`:

```html
{% extends "base.html" %}
{% block title %}ccguard — settings{% endblock %}
{% block content %}
<h2 class="text-2xl font-semibold mb-6">Settings</h2>

<section class="bg-white rounded-lg shadow p-4 mb-6">
    <h3 class="font-semibold mb-3">Agent tokens</h3>
    {% if new_token %}
    <div class="bg-emerald-50 border border-emerald-200 p-3 rounded mb-3 text-sm">
        New token (copy now — won't be shown again):
        <code class="font-mono break-all">{{ new_token }}</code>
    </div>
    {% endif %}
    <table class="w-full text-sm mb-4">
        <thead><tr class="text-left text-slate-500 border-b">
            <th class="py-2">Label</th><th>Created</th><th>Last used</th><th></th>
        </tr></thead>
        <tbody>
        {% for t in tokens %}
        <tr class="border-b last:border-0">
            <td class="py-2">{{ t.label }}</td>
            <td>{{ t.created_at.isoformat(timespec="minutes") }}</td>
            <td>{{ t.last_used_at.isoformat(timespec="minutes") if t.last_used_at else "-" }}</td>
            <td>
                <form method="POST" action="/settings/tokens/{{ t.id }}/revoke" class="inline">
                    <input type="hidden" name="csrf_token" value="{{ csrf_token }}" />
                    <button class="text-red-600 hover:underline">revoke</button>
                </form>
            </td>
        </tr>
        {% else %}
        <tr><td colspan="4" class="py-3 text-slate-400">No tokens yet.</td></tr>
        {% endfor %}
        </tbody>
    </table>
    <form method="POST" action="/settings/tokens" class="flex gap-2 items-end">
        <input type="hidden" name="csrf_token" value="{{ csrf_token }}" />
        <label class="block text-sm">
            New token label
            <input type="text" name="label" required class="block rounded border-slate-300 mt-1" />
        </label>
        <button class="bg-slate-900 text-white rounded px-4 py-2 text-sm">Create token</button>
    </form>
</section>

<section class="bg-white rounded-lg shadow p-4">
    <h3 class="font-semibold mb-3">About</h3>
    <ul class="text-sm space-y-1 text-slate-600">
        <li>Server version: {{ server_version }}</li>
        <li>Admin user: <code>{{ user }}</code></li>
    </ul>
</section>
{% endblock %}
```

- [ ] **Step 4: Add routes**

In `src/ccguard/server/web/routes.py` append:

```python
@router.get("/settings", response_class=HTMLResponse)
def settings_page(
    request: Request,
    user: str = Depends(require_session),
    session: Session = Depends(get_session),
) -> HTMLResponse:
    from ccguard.server.services.token_service import list_tokens
    return templates.TemplateResponse(
        request,
        "settings.html",
        {
            "user": user,
            "tokens": list_tokens(session),
            "new_token": request.session.pop("new_token", None) if hasattr(request, "session") else None,
            "server_version": "0.1.0",
            "csrf_token": _csrf_for(request),
        },
    )


@router.post("/settings/tokens")
def settings_create_token(
    request: Request,
    label: str = Form(...),
    user: str = Depends(require_session),
    _csrf: None = Depends(require_csrf),
    session: Session = Depends(get_session),
) -> RedirectResponse:
    from ccguard.server.services.token_service import create_token
    raw = create_token(session, label=label)
    # Flash via query param (no real flash storage in MVP).
    resp = RedirectResponse(url=f"/settings?new_token={raw}", status_code=303)
    return resp


@router.post("/settings/tokens/{token_id}/revoke")
def settings_revoke_token(
    request: Request,
    token_id: int,
    user: str = Depends(require_session),
    _csrf: None = Depends(require_csrf),
    session: Session = Depends(get_session),
) -> RedirectResponse:
    from ccguard.server.services.token_service import revoke_token
    revoke_token(session, token_id)
    return RedirectResponse(url="/settings", status_code=303)
```

Update the `settings_page` handler to read `new_token` from query param instead of session:

```python
    new_token = request.query_params.get("new_token")
```

and remove the broken `request.session` reference.

- [ ] **Step 5: Run test, verify it passes**

Run: `.venv/bin/pytest tests/integration/test_web_smoke.py::test_settings_create_and_revoke_token -v`
Expected: PASS.

- [ ] **Step 6: Commit**

```bash
git add src/ccguard/server/web/ tests/integration/test_web_smoke.py
git commit -m "feat(settings): agent token CRUD via web"
```

### Task 9.2: Wire token_service into agent auth path

**Files:**
- Modify: `src/ccguard/server/api/deps.py`
- Modify: `src/ccguard/server/config.py`
- Test: extend `tests/integration/test_server_auth.py`

- [ ] **Step 1: Read existing auth dep**

Run: `cat src/ccguard/server/api/deps.py`
Note: `is_token_valid` is currently a static method on `ServerConfig`.

- [ ] **Step 2: Write failing test**

Append to `tests/integration/test_server_auth.py`:

```python
def test_db_token_authenticates_agent(monkeypatch: pytest.MonkeyPatch) -> None:
    from ccguard.server.main import create_app
    from ccguard.server.services.token_service import create_token
    from sqlmodel import Session

    monkeypatch.delenv("CCGUARD_TOKENS", raising=False)
    monkeypatch.setenv("CCGUARD_DB_URL", "sqlite://")
    app = create_app()
    client = TestClient(app)
    with Session(app.state.engine) as s:
        raw = create_token(s, label="dev")

    r = client.get("/api/v1/policy", headers={"X-CCGuard-Token": raw})
    # Need a published policy for the request to succeed, but it shouldn't 401.
    assert r.status_code != 401
```

- [ ] **Step 3: Run test, verify it fails**

Run: `.venv/bin/pytest tests/integration/test_server_auth.py::test_db_token_authenticates_agent -v`
Expected: FAIL (current `require_token` only checks env config).

- [ ] **Step 4: Update `require_token` to consult DB first**

In `src/ccguard/server/api/deps.py` replace `require_token` body:

```python
def require_token(
    x_ccguard_token: Annotated[str | None, Header(alias="X-CCGuard-Token")] = None,
    session: Session = Depends(get_session),
    config: ServerConfig = Depends(get_config),
) -> str:
    from ccguard.server.services.token_service import is_token_valid as db_valid

    if not x_ccguard_token:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="invalid token")
    if db_valid(session, x_ccguard_token):
        return x_ccguard_token
    # Fallback to env-configured tokens (bootstrap mode, before DB has any).
    if config.is_token_valid(x_ccguard_token):
        return x_ccguard_token
    raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="invalid token")
```

(Adjust imports — `Depends`, `Session`.)

- [ ] **Step 5: Run test, verify it passes**

Run: `.venv/bin/pytest tests/integration/test_server_auth.py -v`
Expected: all PASS.

- [ ] **Step 6: Commit**

```bash
git add src/ccguard/server/api/deps.py tests/integration/test_server_auth.py
git commit -m "feat(auth): require_token consults AgentToken table"
```

---

### Task 9.3: Bootstrap migration: CCGUARD_TOKENS env → AgentToken table

**Files:**
- Modify: `src/ccguard/server/main.py` (in lifespan)
- Test: `tests/unit/test_token_bootstrap.py`

- [ ] **Step 1: Write failing test**

Create `tests/unit/test_token_bootstrap.py`:

```python
"""On startup, env CCGUARD_TOKENS are migrated into AgentToken if table is empty."""

from __future__ import annotations

from sqlmodel import Session, SQLModel, create_engine

from ccguard.server.db.models import AgentToken
from ccguard.server.services.token_service import bootstrap_env_tokens


def test_bootstrap_inserts_when_table_empty() -> None:
    engine = create_engine("sqlite://")
    SQLModel.metadata.create_all(engine)
    with Session(engine) as s:
        bootstrap_env_tokens(s, env_tokens=["dev-token", "prod-token"])
        rows = list(s.exec(AgentToken.__table__.select()))  # type: ignore[attr-defined]
        assert len(rows) == 2
        assert all(r.label.startswith("env-bootstrap-") for r in rows)


def test_bootstrap_skips_when_table_nonempty() -> None:
    engine = create_engine("sqlite://")
    SQLModel.metadata.create_all(engine)
    with Session(engine) as s:
        s.add(AgentToken(label="existing", token_hash="abc"))
        s.commit()
        bootstrap_env_tokens(s, env_tokens=["dev-token"])
        rows = list(s.exec(AgentToken.__table__.select()))  # type: ignore[attr-defined]
        assert len(rows) == 1
```

- [ ] **Step 2: Run test, verify it fails**

Run: `.venv/bin/pytest tests/unit/test_token_bootstrap.py -v`
Expected: FAIL (function missing).

- [ ] **Step 3: Implement**

In `src/ccguard/server/services/token_service.py` append:

```python
def bootstrap_env_tokens(session: Session, *, env_tokens: list[str]) -> None:
    """Migrate env-configured tokens into AgentToken if the table is empty.

    Runs once on startup. Idempotent: if any AgentToken rows exist, no-op.
    """
    existing = session.exec(select(AgentToken).limit(1)).first()
    if existing is not None:
        return
    for i, raw in enumerate(env_tokens):
        if not raw:
            continue
        session.add(
            AgentToken(label=f"env-bootstrap-{i}", token_hash=_hash(raw))
        )
    session.commit()
```

- [ ] **Step 4: Call from lifespan**

In `src/ccguard/server/main.py` lifespan, after `init_db(engine)`, add:

```python
    from sqlmodel import Session
    from ccguard.server.services.token_service import bootstrap_env_tokens
    with Session(engine) as s:
        bootstrap_env_tokens(s, env_tokens=cfg.tokens)
```

(`cfg.tokens` is the existing list of raw strings from `CCGUARD_TOKENS`.)

- [ ] **Step 5: Run tests**

Run: `.venv/bin/pytest tests/unit/test_token_bootstrap.py -v`
Expected: PASS.

- [ ] **Step 6: Commit**

```bash
git add src/ccguard/server/services/token_service.py src/ccguard/server/main.py tests/unit/test_token_bootstrap.py
git commit -m "feat(tokens): bootstrap env CCGUARD_TOKENS into AgentToken on startup"
```

### Task 9.4: Change admin password

**Files:**
- Modify: `src/ccguard/server/web/templates/settings.html`
- Modify: `src/ccguard/server/web/routes.py`
- Test: extend `tests/integration/test_web_smoke.py`

- [ ] **Step 1: Write failing test**

Append to `tests/integration/test_web_smoke.py`:

```python
def test_change_admin_password(monkeypatch: pytest.MonkeyPatch, tmp_path) -> None:
    from ccguard.server.services.auth_service import (
        create_session, hash_password, verify_password,
    )
    from ccguard.server.web.csrf import generate_csrf_token
    from sqlmodel import Session

    monkeypatch.setenv("CCGUARD_ADMIN_PASSWORD_HASH", hash_password("oldpass"))
    monkeypatch.setenv("CCGUARD_DB_URL", "sqlite://")
    monkeypatch.setenv("CCGUARD_SESSION_SECRET", "s")
    # Path where new hash gets written.
    monkeypatch.setenv("CCGUARD_ADMIN_HASH_FILE", str(tmp_path / "admin.hash"))
    app = create_app()
    client = TestClient(app)
    with Session(app.state.engine) as s:
        sid = create_session(s, user_id="admin")
    csrf = generate_csrf_token(secret="s", session_id=sid)

    r = client.post(
        "/settings/password",
        data={
            "csrf_token": csrf,
            "current_password": "oldpass",
            "new_password": "newpass!",
        },
        cookies={"ccg_session": sid},
        follow_redirects=False,
    )
    assert r.status_code == 303
    # Hash file written, contains a hash that verifies for "newpass!".
    written = (tmp_path / "admin.hash").read_text().strip()
    assert verify_password("newpass!", written) is True
```

- [ ] **Step 2: Run test, verify it fails**

Run: `.venv/bin/pytest tests/integration/test_web_smoke.py::test_change_admin_password -v`
Expected: FAIL.

- [ ] **Step 3: Add config field**

In `src/ccguard/server/config.py` `ServerConfig` add:

```python
    admin_hash_file: str | None = None
```

And in `load()`:

```python
            admin_hash_file=os.environ.get("CCGUARD_ADMIN_HASH_FILE"),
```

- [ ] **Step 4: Add password change form section to settings.html**

In `src/ccguard/server/web/templates/settings.html` before the "About" section, add:

```html
<section class="bg-white rounded-lg shadow p-4 mb-6">
    <h3 class="font-semibold mb-3">Change admin password</h3>
    <form method="POST" action="/settings/password" class="space-y-3 text-sm max-w-md">
        <input type="hidden" name="csrf_token" value="{{ csrf_token }}" />
        <label class="block">Current password
            <input type="password" name="current_password" required
                   class="mt-1 block w-full rounded border-slate-300" /></label>
        <label class="block">New password
            <input type="password" name="new_password" required minlength="6"
                   class="mt-1 block w-full rounded border-slate-300" /></label>
        <button class="bg-slate-900 text-white rounded px-4 py-2">Change password</button>
        {% if password_msg %}<p class="text-sm text-emerald-600">{{ password_msg }}</p>{% endif %}
    </form>
</section>
```

Update `settings_page` to read `password_msg` from query string:

```python
            "password_msg": request.query_params.get("password_msg"),
```

- [ ] **Step 5: Add route**

In `src/ccguard/server/web/routes.py` append:

```python
@router.post("/settings/password")
def settings_change_password(
    request: Request,
    current_password: str = Form(...),
    new_password: str = Form(..., min_length=6),
    user: str = Depends(require_session),
    _csrf: None = Depends(require_csrf),
) -> RedirectResponse:
    from pathlib import Path

    from ccguard.server.services.auth_service import hash_password, verify_password

    cfg = _config(request)
    if cfg.admin_password_hash is None or not verify_password(current_password, cfg.admin_password_hash):
        raise HTTPException(status_code=401, detail="current password incorrect")

    new_hash = hash_password(new_password)
    if cfg.admin_hash_file:
        Path(cfg.admin_hash_file).write_text(new_hash + "\n")
    # Hot-reload in process (until restart).
    cfg.admin_password_hash = new_hash
    return RedirectResponse(url="/settings?password_msg=Password+changed", status_code=303)
```

- [ ] **Step 6: Run test, verify it passes**

Run: `.venv/bin/pytest tests/integration/test_web_smoke.py::test_change_admin_password -v`
Expected: PASS.

- [ ] **Step 7: Commit**

```bash
git add src/ccguard/server/web/ src/ccguard/server/config.py tests/integration/test_web_smoke.py
git commit -m "feat(settings): admin password change writes to hash file"
```

---

## Phase 10: Docker + smoke test

**Goal:** Server image builds, web UI works in compose, single E2E smoke test green.

### Task 10.1: Update Dockerfile.server with new deps

**Files:**
- Modify: `docker/Dockerfile.server`
- Modify: `docker/docker-compose.yml`

- [ ] **Step 1: Read existing Dockerfile**

Run: `cat docker/Dockerfile.server`

- [ ] **Step 2: Verify build works locally (no changes needed since deps are in pyproject)**

Run: `cd docker && docker compose up -d --build server`
Expected: container builds and starts healthy.

- [ ] **Step 3: Add admin password to compose**

In `docker/docker-compose.yml` under `services.server.environment` add:

```yaml
      CCGUARD_ADMIN_USER: "admin"
      CCGUARD_ADMIN_PASSWORD_HASH: "$2b$12$KIXxPfQQwxKkLb1lXkA/Q.RHEsXgxOuEFRl8kPM7Wt5q5XkPaTzga"  # bcrypt of "admin"
      CCGUARD_SESSION_SECRET: "demo-session-secret-change-me"
```

- [ ] **Step 4: Restart**

Run: `cd docker && docker compose up -d --build server`

- [ ] **Step 5: Manually verify**

Open `http://localhost:8080/login` in a browser, log in with `admin` / `admin`.
Expected: Overview page loads, fleet table shows existing test machine.

- [ ] **Step 6: Commit**

```bash
git add docker/docker-compose.yml
git commit -m "chore(docker): add admin credentials to compose env"
```

### Task 10.2: E2E smoke test

**Files:**
- Create: `tests/e2e/test_web_e2e.py`

- [ ] **Step 1: Write E2E test**

Create `tests/e2e/test_web_e2e.py`:

```python
"""E2E smoke: web UI works end-to-end through Docker compose.

Requires `docker compose up -d server` to be running.
"""

from __future__ import annotations

import os

import httpx
import pytest

BASE_URL = os.environ.get("CCGUARD_E2E_URL", "http://localhost:8080")


@pytest.mark.e2e
def test_web_login_and_overview() -> None:
    with httpx.Client(base_url=BASE_URL, follow_redirects=False) as client:
        # Unauthenticated → redirect to /login
        r = client.get("/")
        assert r.status_code in (302, 303, 307)

        # Log in
        r = client.post("/login", data={"username": "admin", "password": "admin"})
        assert r.status_code == 303
        sid = r.cookies["ccg_session"]

        # Overview renders
        r = client.get("/", cookies={"ccg_session": sid})
        assert r.status_code == 200
        assert "Overview" in r.text

        # Fleet partial works
        r = client.get(
            "/_partials/overview/fleet-table",
            cookies={"ccg_session": sid},
        )
        assert r.status_code == 200
```

- [ ] **Step 2: Run E2E test**

Run: `.venv/bin/pytest tests/e2e/test_web_e2e.py -v -m e2e`
Expected: PASS (server already running from previous task).

- [ ] **Step 3: Run full test suite**

Run: `.venv/bin/pytest -q`
Expected: all unit + integration green; e2e green if server up, skipped otherwise.

- [ ] **Step 4: Final commit**

```bash
git add tests/e2e/test_web_e2e.py
git commit -m "test(e2e): web UI smoke test via docker compose"
```

---

## Open questions deferred to runtime (from spec section "Open questions")

These don't block implementation. Default during build, revisit after manual QA:

1. **Sidebar icons** — Default: no icons, text only. Add later if visual density needs it.
2. **Date/time display** — Default: UTC ISO strings in templates. Add JS local-time conversion later if needed.
3. **Inventory lazy-loading** — Default: render full inventory on `/machines/{id}` GET. If page becomes slow (>1s), split into `_inventory_*` partials lazy-loaded by HTMX on tab click.

## Wrap-up

After Phase 10, the project should have:

- 6 new pages (`/`, `/machines`, `/machines/{id}`, `/findings`, `/policy`, `/policy/history`, `/settings`).
- 3 new SQL tables (`PolicyVersion`, `WebSession`, `AgentToken`).
- 5 new services (`auth_service`, `policy_service`, `machine_service`, `finding_service`, `token_service`).
- ~25 new unit and integration tests on top of the existing 99+.
- One E2E docker-compose smoke test.

Each phase ends with all tests green and a clean commit, so you can safely pause between any two phases.
