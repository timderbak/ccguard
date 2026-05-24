"""ccguard web UI routes (Jinja2 + HTMX)."""
from __future__ import annotations

from pathlib import Path

import yaml
from fastapi import APIRouter, Depends, Form, HTTPException, Request, status
from fastapi.responses import HTMLResponse, RedirectResponse, Response
from fastapi.templating import Jinja2Templates
from pydantic import ValidationError
from sqlmodel import Session, select

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
    baseline = yaml.safe_load(current.yaml_text) if current else None
    try:
        yaml_text = form_to_yaml(
            dict(form), current_revision=current_rev, baseline=baseline,
        )
    except ValidationError as e:
        raise HTTPException(status_code=422, detail=str(e))
    save_draft(session, yaml_text=yaml_text, user_id=user)
    return RedirectResponse(url="/policy", status_code=303)


@router.post("/policy/publish")
async def publish_policy(
    request: Request,
    user: str = Depends(require_session),
    _csrf: None = Depends(require_csrf),
    session: Session = Depends(get_session),
) -> RedirectResponse:
    from ccguard.server.services.policy_service import (
        get_current_published,
        get_draft,
        publish_draft,
        save_draft,
    )
    from ccguard.server.web.policy_form import form_to_yaml

    form = await request.form()
    keys = list(form.keys())
    has_section_data = any(
        k.startswith(prefix + ".")
        for k in keys
        for prefix in ("mcp_servers", "network", "commands", "skills", "hooks", "agents", "env")
    )
    if has_section_data:
        current = get_current_published(session)
        current_rev = current.revision if current else 0
        baseline = yaml.safe_load(current.yaml_text) if current else None
        try:
            yaml_text = form_to_yaml(
                dict(form), current_revision=current_rev, baseline=baseline,
            )
        except ValidationError as e:
            raise HTTPException(status_code=422, detail=str(e))
        save_draft(session, yaml_text=yaml_text, user_id=user)
    if get_draft(session) is None:
        raise HTTPException(status_code=400, detail="no draft to publish")
    publish_draft(session, user_id=user)
    return RedirectResponse(url="/policy", status_code=303)


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
            "new_token": request.query_params.get("new_token"),
            "password_msg": request.query_params.get("password_msg"),
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
    return RedirectResponse(url=f"/settings?new_token={raw}", status_code=303)


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
