"""ccguard web UI routes (Jinja2 + HTMX)."""
from __future__ import annotations

import json
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


@router.get("/audit", response_class=HTMLResponse)
def audit_page(
    request: Request,
    machine_id: str = "",
    tool_name: str = "",
    decision: str = "",
    timeframe: str = "24h",
    user: str = Depends(require_session),
    session: Session = Depends(get_session),
) -> HTMLResponse:
    from ccguard.server.services.tool_use_service import list_events, timeline_buckets

    if decision not in ("allow", "deny", "error", ""):
        decision = ""
    if timeframe not in ("1h", "24h", "7d"):
        timeframe = "24h"
    events, total = list_events(
        session,
        machine_id_like=machine_id or None,
        tool_name=tool_name or None,
        decision=decision or None,
        timeframe=timeframe,  # type: ignore[arg-type]
        limit=200,
    )
    # Timeline always renders the last 24 hours (UI-SPEC card heading
    # "Активность за 24 часа") regardless of the user-selected timeframe.
    buckets = timeline_buckets(
        session,
        hours=24,
        machine_id_like=machine_id or None,
        tool_name=tool_name or None,
        decision=decision or None,
    )
    max_count = max((b["count"] for b in buckets), default=0)
    return templates.TemplateResponse(
        request,
        "audit_feed.html",
        {
            "user": user,
            "filters": {
                "machine_id": machine_id,
                "tool_name": tool_name,
                "decision": decision,
                "timeframe": timeframe,
            },
            "events": events,
            "total": total,
            "limit": 200,
            "buckets": buckets,
            "max_count": max_count,
            "csrf_token": _csrf_for(request),
        },
    )


@router.get("/_partials/audit/timeline", response_class=HTMLResponse)
def audit_timeline_partial(
    request: Request,
    machine_id: str = "",
    tool_name: str = "",
    decision: str = "",
    timeframe: str = "24h",
    _user: str = Depends(require_session),
    session: Session = Depends(get_session),
) -> HTMLResponse:
    """HTMX-polled timeline partial.

    The ``timeframe`` query param is accepted (echoed from the audit filter
    form via ``hx-include="closest form"``) but intentionally ignored: per
    01-UI-SPEC the chart window is fixed at 24 hours (card heading
    "Активность за 24 часа"). Filtering still applies on machine_id /
    tool_name / decision so the polled chart honors active filters.
    """
    if decision not in ("allow", "deny", "error", ""):
        decision = ""
    # timeframe accepted but unused — see docstring.
    _ = timeframe
    from ccguard.server.services.tool_use_service import timeline_buckets

    buckets = timeline_buckets(
        session,
        hours=24,
        machine_id_like=machine_id or None,
        tool_name=tool_name or None,
        decision=decision or None,
    )
    max_count = max((b["count"] for b in buckets), default=0)
    return templates.TemplateResponse(
        request,
        "components/_audit_timeline.html",
        {"buckets": buckets, "max_count": max_count},
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
    cfg.admin_password_hash = new_hash
    return RedirectResponse(url="/settings?password_msg=Пароль+изменён", status_code=303)


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


@router.get("/anomalies", response_class=HTMLResponse)
def anomalies_feed_page(
    request: Request,
    user: str = Depends(require_session),
) -> HTMLResponse:
    """Main /anomalies page: matrix card hydrated by HTMX from /_partials/anomalies/matrix."""
    return templates.TemplateResponse(
        request,
        "anomalies_feed.html",
        {"user": user, "csrf_token": _csrf_for(request)},
    )


@router.get("/_partials/anomalies/matrix", response_class=HTMLResponse)
def anomalies_matrix_partial(
    request: Request,
    _user: str = Depends(require_session),
    session: Session = Depends(get_session),
) -> HTMLResponse:
    """HTMX-polled matrix partial: machines × 4 metrics with CSS sparklines."""
    from datetime import timedelta
    from ccguard.server.db.models import Machine, MachineBaseline
    from ccguard.server.services.anomaly_constants import ALL_METRICS

    machines_rows = list(
        session.exec(select(Machine).order_by(Machine.last_seen.desc()))  # type: ignore[attr-defined]
    )

    # Bulk-load all baselines for these machines (one query, then bucket in-process).
    baselines_by_key: dict[tuple[str, str], MachineBaseline] = {}
    if machines_rows:
        machine_ids = [m.machine_id for m in machines_rows]
        for b in session.exec(
            select(MachineBaseline).where(MachineBaseline.machine_id.in_(machine_ids))  # type: ignore[attr-defined]
        ):
            baselines_by_key[(b.machine_id, b.metric)] = b

    # 14 daily anchor labels, oldest first.
    today = _utcnow_date()
    labels = [(today - timedelta(days=13 - i)).isoformat() for i in range(14)]

    machines_vm = []
    for m in machines_rows:
        cells: dict[str, dict] = {}
        for metric in ALL_METRICS:
            baseline = baselines_by_key.get((m.machine_id, metric))
            cells[metric] = _build_sparkline_cell(baseline, labels)
        machines_vm.append({"id": m.machine_id, "cells": cells})

    return templates.TemplateResponse(
        request,
        "components/_anomalies_matrix.html",
        {"machines": machines_vm, "metrics": list(ALL_METRICS)},
    )


@router.get("/anomalies/{machine_id}/{metric}", response_class=HTMLResponse)
def anomaly_detail(
    request: Request,
    machine_id: str,
    metric: str,
    user: str = Depends(require_session),
    session: Session = Depends(get_session),
) -> HTMLResponse:
    """Drill-down: baseline strip + 14-day timeseries + recent findings."""
    from datetime import timedelta
    from ccguard.server.db.models import FindingRecord, MachineBaseline
    from ccguard.server.services.anomaly_constants import VALID_METRICS, rule_id_for

    if metric not in VALID_METRICS:
        raise HTTPException(status_code=404, detail="unknown metric")

    baseline = session.exec(
        select(MachineBaseline).where(
            MachineBaseline.machine_id == machine_id,  # type: ignore[arg-type]
            MachineBaseline.metric == metric,  # type: ignore[arg-type]
        )
    ).first()

    # 14 daily anchor labels.
    today = _utcnow_date()
    labels = [(today - timedelta(days=13 - i)).isoformat() for i in range(14)]

    # Build per-point view-model. 2px floor on the detail chart.
    if baseline is not None:
        try:
            raw_points = json.loads(baseline.recent_points_json) if baseline.recent_points_json else []
        except (ValueError, TypeError):
            raw_points = []
    else:
        raw_points = []
    # Normalize to length 14 (left-pad with zeros so most recent aligns right).
    if len(raw_points) < 14:
        raw_points = [0.0] * (14 - len(raw_points)) + [float(v) for v in raw_points]
    else:
        raw_points = [float(v) for v in raw_points[-14:]]

    max_val = max(raw_points) if any(v > 0 for v in raw_points) else 1.0
    baseline_ready = bool(baseline and baseline.baseline_ready)
    mean = float(baseline.mean) if baseline else 0.0
    stdev = float(baseline.stdev) if baseline else 0.0

    points_vm = []
    for label, value in zip(labels, raw_points):
        height_pct = (value / max_val) * 100.0 if max_val > 0 else 0.0
        is_outlier = baseline_ready and stdev > 0 and abs(value - mean) > 3 * stdev
        points_vm.append(
            {
                "value": value,
                "height_pct": round(height_pct, 2),
                "label": label,
                "is_outlier": is_outlier,
            }
        )

    # Baseline band: mean ± 3σ, normalized to chart max.
    # WR-03: clamp top and bottom in absolute terms first, then derive height
    # from the clamped values. Previous code derived height from raw 6σ and
    # let min() truncate, which produced visually misleading bars when the
    # outlier defining max_val pushed (mean + 3σ) > max_val — exactly the
    # anomaly case we care about.
    band_visible = baseline_ready and stdev > 0 and max_val > 0
    if band_visible:
        top_pct = max(0.0, min(100.0, ((mean + 3 * stdev) / max_val) * 100.0))
        bot_pct = max(0.0, min(100.0, ((mean - 3 * stdev) / max_val) * 100.0))
        band_bottom_pct = bot_pct
        band_height_pct = max(0.0, top_pct - bot_pct)
    else:
        band_bottom_pct = 0.0
        band_height_pct = 0.0

    # Recent findings for this (machine, metric).
    rid = rule_id_for(metric)
    finding_rows = list(
        session.exec(
            select(FindingRecord)
            .where(
                FindingRecord.machine_id == machine_id,  # type: ignore[arg-type]
                FindingRecord.rule_id == rid,  # type: ignore[arg-type]
            )
            .order_by(FindingRecord.discovered_at.desc())  # type: ignore[attr-defined]
            .limit(50)
        )
    )
    findings_vm = []
    for r in finding_rows:
        try:
            payload = json.loads(r.payload_json) if r.payload_json else {}
        except (ValueError, TypeError):
            payload = {}
        # WR-02: sigma_distance is None for degenerate-stdev findings; render
        # as "∞" in that case rather than letting the template format ``None``.
        # Pass both a pre-formatted display string AND a numeric flag for the
        # red-coloring threshold check so the template stays simple.
        raw_sigma = payload.get("sigma_distance")
        is_high_sigma = False
        if raw_sigma is None:
            sigma_display = "∞"
            is_high_sigma = True  # degenerate (stdev=0) outlier → always emphasize
        else:
            try:
                sigma_num = float(raw_sigma)
                sigma_display = f"{sigma_num:+.1f}"
                is_high_sigma = abs(sigma_num) > 3
            except (TypeError, ValueError):
                sigma_display = "—"
        findings_vm.append(
            {
                "discovered_at": r.discovered_at,
                "observed_value": payload.get("observed_value", "—"),
                "sigma_distance": sigma_display,
                "is_high_sigma": is_high_sigma,
                "rule_id": r.rule_id,
            }
        )

    return templates.TemplateResponse(
        request,
        "anomaly_detail.html",
        {
            "user": user,
            "machine_id": machine_id,
            "metric": metric,
            "baseline": baseline,
            "baseline_ready": baseline_ready,
            "points": points_vm,
            "band_visible": band_visible,
            "band_bottom_pct": round(band_bottom_pct, 2),
            "band_height_pct": round(band_height_pct, 2),
            "findings": findings_vm,
            "csrf_token": _csrf_for(request),
        },
    )


def _utcnow_date():
    from datetime import UTC, datetime
    return datetime.now(UTC).date()


def _build_sparkline_cell(baseline, labels: list[str]) -> dict:
    """Build the per-cell sparkline view-model (warm-up or 14 bars).

    Cell shape (consumed by components/_anomalies_matrix.html):
      {warmup: bool, points: [{value, height_pct, label}], last_value, is_outlier}
    """
    if baseline is None or not baseline.baseline_ready:
        return {"warmup": True, "points": [], "last_value": None, "is_outlier": False}
    try:
        raw = json.loads(baseline.recent_points_json) if baseline.recent_points_json else []
    except (ValueError, TypeError):
        raw = []
    raw = [float(v) for v in raw]
    if not raw:
        # baseline_ready but empty points — degenerate. Render as warm-up.
        return {"warmup": True, "points": [], "last_value": None, "is_outlier": False}
    # Align 14 right-aligned points.
    if len(raw) < 14:
        raw = [0.0] * (14 - len(raw)) + raw
    else:
        raw = raw[-14:]
    max_val = max(raw) if any(v > 0 for v in raw) else 1.0
    last_value = raw[-1]
    mean = float(baseline.mean)
    stdev = float(baseline.stdev)
    is_outlier = stdev > 0 and abs(last_value - mean) > 3 * stdev
    points = [
        {
            "value": v,
            "height_pct": round((v / max_val) * 100.0, 2) if max_val > 0 else 0.0,
            "label": labels[i] if i < len(labels) else "",
        }
        for i, v in enumerate(raw)
    ]
    return {
        "warmup": False,
        "points": points,
        "last_value": last_value,
        "is_outlier": is_outlier,
    }


@router.get("/_partials/anomalies/overview", response_class=HTMLResponse)
def anomalies_overview_partial(
    request: Request,
    _user: str = Depends(require_session),
    session: Session = Depends(get_session),
) -> HTMLResponse:
    """HTMX-polled top-5 recent anomaly findings (rule_id LIKE 'anomaly.%')."""
    from ccguard.server.db.models import FindingRecord

    rows = list(
        session.exec(
            select(FindingRecord)
            .where(FindingRecord.rule_id.like("anomaly.%"))  # type: ignore[attr-defined]
            .order_by(FindingRecord.discovered_at.desc())  # type: ignore[attr-defined]
            .limit(5)
        )
    )
    items = []
    for r in rows:
        metric = r.rule_id.removeprefix("anomaly.")
        try:
            payload = json.loads(r.payload_json) if r.payload_json else {}
        except (ValueError, TypeError):
            payload = {}
        # WR-02: sigma_distance may be None (degenerate stdev=0 baseline) or
        # a non-numeric value if payload is malformed. Coerce to a display
        # string so the template can render uniformly without per-cell logic.
        raw_sigma = payload.get("sigma_distance")
        if raw_sigma is None:
            sigma_display = "∞"
        else:
            try:
                sigma_display = f"{round(float(raw_sigma), 1):+.1f}"
            except (TypeError, ValueError):
                sigma_display = "—"
        items.append(
            {
                "machine_id": r.machine_id,
                "metric": metric,
                "observed_value": payload.get("observed_value", "—"),
                "sigma_distance": sigma_display,
                "ts_short": r.discovered_at.strftime("%Y-%m-%d %H:%M"),
            }
        )
    return templates.TemplateResponse(
        request,
        "components/_anomalies_overview.html",
        {"items": items},
    )
