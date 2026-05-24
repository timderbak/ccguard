"""ccguard web UI routes (Jinja2 + HTMX)."""
from __future__ import annotations

from pathlib import Path

from fastapi import APIRouter, Depends, Form, HTTPException, Request, status
from fastapi.responses import HTMLResponse, RedirectResponse, Response
from fastapi.templating import Jinja2Templates
from sqlmodel import Session

from ccguard.server.api.deps import get_session
from ccguard.server.config import ServerConfig
from ccguard.server.web.csrf import generate_csrf_token, verify_csrf_token
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
SESSION_TTL_HOURS = 24


def _csrf_for(request: Request) -> str:
    sid = request.cookies.get(COOKIE_NAME) or ""
    return generate_csrf_token(secret=_config(request).session_secret, session_id=sid)


def _config(request: Request) -> ServerConfig:
    cfg = getattr(request.app.state, "config", None)
    if cfg is None:
        raise RuntimeError("server config not initialized on app.state")
    return cfg


def require_session(
    request: Request,
    session: Session = Depends(get_session),
) -> str:
    sid = request.cookies.get(COOKIE_NAME)
    if sid and session_is_valid(session, sid):
        return sid
    accept = request.headers.get("accept", "")
    if "text/html" in accept:
        raise HTTPException(
            status_code=status.HTTP_307_TEMPORARY_REDIRECT,
            headers={"Location": "/login"},
        )
    raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="not authenticated")


@router.get("/login", response_class=HTMLResponse)
def login_form(request: Request) -> HTMLResponse:
    return templates.TemplateResponse(request, "login.html", {})


@router.post("/login")
def login_submit(
    request: Request,
    username: str = Form(...),
    password: str = Form(...),
    session: Session = Depends(get_session),
) -> Response:
    cfg = _config(request)
    if (
        not cfg.admin_password_hash
        or username != cfg.admin_user
        or not verify_password(password, cfg.admin_password_hash)
    ):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="invalid credentials")
    sid = create_session(session, user_id=username, ttl_hours=SESSION_TTL_HOURS)
    resp = RedirectResponse(url="/", status_code=status.HTTP_303_SEE_OTHER)
    resp.set_cookie(
        key=COOKIE_NAME,
        value=sid,
        max_age=SESSION_TTL_HOURS * 3600,
        httponly=True,
        samesite="lax",
        secure=cfg.cookie_secure,
        path="/",
    )
    return resp


def require_csrf(request: Request, csrf_token: str = Form("")) -> None:
    sid = request.cookies.get(COOKIE_NAME) or ""
    cfg = _config(request)
    if not verify_csrf_token(csrf_token, secret=cfg.session_secret, session_id=sid):
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="invalid CSRF token")


@router.post("/logout")
def logout(
    request: Request,
    session: Session = Depends(get_session),
    _csrf: None = Depends(require_csrf),
) -> Response:
    sid = request.cookies.get(COOKIE_NAME)
    if sid:
        delete_session(session, sid)
    resp = RedirectResponse(url="/login", status_code=status.HTTP_303_SEE_OTHER)
    resp.delete_cookie(COOKIE_NAME, path="/")
    return resp


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
        {"user": user, "machines": machines, "csrf_token": _csrf_for(request)},
    )


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
