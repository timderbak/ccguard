"""ccguard web UI routes (Jinja2 + HTMX)."""
from __future__ import annotations

import json
import math
from datetime import UTC, datetime, timedelta
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
    from ccguard.server.services.fleet_risk import compute_fleet_risk
    from ccguard.server.services.machine_service import list_machines_with_status
    machines = list_machines_with_status(session)
    fleet_risk = compute_fleet_risk(session, limit=10)
    return templates.TemplateResponse(
        request,
        "overview.html",
        {
            "user": user,
            "machines": machines,
            "fleet_risk": fleet_risk,
            "csrf_token": _csrf_for(request),
        },
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
    from ccguard.server.web.finding_view import build_explainable_findings
    machine = session.get(Machine, machine_id)
    if machine is None:
        raise HTTPException(status_code=404)
    findings = get_findings_for_machine(session, machine_id)
    return templates.TemplateResponse(
        request,
        "machine_detail.html",
        {
            "user": user,
            "machine": machine,
            "inventory": get_latest_inventory_json(session, machine_id),
            "findings": build_explainable_findings(findings),
            "csrf_token": _csrf_for(request),
        },
    )


@router.get("/admin/proposed-signals", response_class=HTMLResponse)
def proposed_signals_page(
    request: Request,
    user: str = Depends(require_session),
    session: Session = Depends(get_session),
) -> HTMLResponse:
    """Admin list of LLM/manual-drafted catalog signals awaiting approval."""
    from ccguard.server.services import proposed_signal_service as svc

    def _wrap(row) -> dict:
        try:
            draft = json.loads(row.draft_json)
        except (ValueError, TypeError):
            draft = {"id": "(corrupt)", "attack_technique": "?", "pattern": "?", "description": ""}
        return {"row": row, "draft": draft}

    return templates.TemplateResponse(
        request,
        "proposed_signals.html",
        {
            "user": user,
            "pending": [_wrap(r) for r in svc.list_pending(session)],
            "reviewed": [_wrap(r) for r in svc.list_reviewed(session, limit=20)],
            "csrf_token": _csrf_for(request),
        },
    )


@router.post("/admin/proposed-signals/draft-from-text")
def proposed_signals_draft(
    request: Request,
    draft_json: str = Form(...),
    _user: str = Depends(require_session),
    _csrf: None = Depends(require_csrf),
    session: Session = Depends(get_session),
) -> RedirectResponse:
    """Manual paste path (E1). E2 swaps this for an LLM-drafted variant."""
    from ccguard.server.services import proposed_signal_service as svc

    try:
        draft = json.loads(draft_json)
        if not isinstance(draft, dict):
            raise ValueError("draft_json must be a JSON object")
        svc.propose(session, draft=draft, source_kind="manual", source_title="manual paste")
    except (ValueError, svc.InvalidDraft) as e:
        raise HTTPException(status_code=400, detail=f"invalid draft: {e}") from e
    return RedirectResponse(url="/admin/proposed-signals", status_code=303)


@router.post("/admin/proposed-signals/{row_id}/approve")
def proposed_signals_approve(
    row_id: int,
    request: Request,
    user: str = Depends(require_session),
    _csrf: None = Depends(require_csrf),
    session: Session = Depends(get_session),
) -> RedirectResponse:
    from ccguard.server.services import proposed_signal_service as svc

    try:
        svc.approve(session, row_id, reviewed_by=user)
    except svc.InvalidDraft as e:
        raise HTTPException(status_code=400, detail=str(e)) from e
    except svc.NotPending as e:
        raise HTTPException(status_code=409, detail=str(e)) from e
    return RedirectResponse(url="/admin/proposed-signals", status_code=303)


@router.post("/admin/proposed-signals/{row_id}/reject")
def proposed_signals_reject(
    row_id: int,
    request: Request,
    reason: str = Form(""),
    user: str = Depends(require_session),
    _csrf: None = Depends(require_csrf),
    session: Session = Depends(get_session),
) -> RedirectResponse:
    from ccguard.server.services import proposed_signal_service as svc

    try:
        svc.reject(session, row_id, reviewed_by=user, reason=reason or "(no reason)")
    except svc.NotPending as e:
        raise HTTPException(status_code=409, detail=str(e)) from e
    return RedirectResponse(url="/admin/proposed-signals", status_code=303)


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


def _finding_view_model(row) -> object:
    """Wrap a :class:`FindingRecord` for template consumption.

    Adds a ``.details`` dict parsed from ``payload_json`` so templates can
    read ``finding.details.risk_score`` / ``.category`` / ``.file_hash``
    uniformly. LLM-scanner findings expose these keys; older findings get an
    empty dict so the badge template renders the em-dash branch.
    """

    class _FindingVM:
        # WR-08: __slots__ was used here but invites future maintainers to
        # silently break when adding new attrs. Plain class (no slots) is
        # the right shape — this is not a hot-path object. The URL-encoding
        # defense referenced below lives in
        # `templates/components/_finding_row.html` (the `urlencode` filter
        # on `finding.details.file_hash` before `hx-post`); the server
        # handler at `/admin/scan/{file_hash}/rescan` separately validates
        # len==64 and hex-only.
        def __init__(self, r) -> None:
            self.discovered_at = r.discovered_at
            self.machine_id = r.machine_id
            self.rule_id = r.rule_id
            self.severity = r.severity
            try:
                payload = json.loads(r.payload_json) if r.payload_json else {}
            except (ValueError, TypeError):
                payload = {}
            if not isinstance(payload, dict):
                payload = {}
            # Normalize details accessor: template uses attribute-style access
            # (``finding.details.risk_score``) — Jinja falls back to item
            # access on plain dicts, which is what we want.
            self.details = payload

    return _FindingVM(row)


@router.get("/findings", response_class=HTMLResponse)
def findings_page(
    request: Request,
    severity: str | None = None,
    rule_id: str | None = None,
    machine_id: str | None = None,
    scope: str | None = None,
    user: str = Depends(require_session),
    session: Session = Depends(get_session),
) -> HTMLResponse:
    from ccguard.server.db.models import FindingRecord
    stmt = select(FindingRecord)
    if severity:
        stmt = stmt.where(FindingRecord.severity == severity)
    if rule_id:
        stmt = stmt.where(FindingRecord.rule_id == rule_id)
    if machine_id:
        stmt = stmt.where(FindingRecord.machine_id == machine_id)
    # Plan 03-05: scope filter — additive AND with rule_id filter above.
    if scope == "llm":
        stmt = stmt.where(FindingRecord.rule_id.like("llm.scan.%"))  # type: ignore[attr-defined]
    elif scope == "non_llm":
        stmt = stmt.where(~FindingRecord.rule_id.like("llm.scan.%"))  # type: ignore[attr-defined]
    stmt = stmt.order_by(FindingRecord.discovered_at.desc()).limit(200)  # type: ignore[attr-defined]
    rows = list(session.exec(stmt))
    findings = [_finding_view_model(r) for r in rows]
    return templates.TemplateResponse(
        request,
        "findings_feed.html",
        {
            "user": user,
            "findings": findings,
            "filters": {
                "severity": severity,
                "rule_id": rule_id,
                "machine_id": machine_id,
                "scope": scope or "all",
            },
            "csrf_token": _csrf_for(request),
        },
    )


_TIMEFRAME_HOURS = {"1h": 1, "24h": 24, "7d": 24 * 7}


def _policy_apply_events(
    session: Session,
    *,
    machine_id_like: str | None,
    timeframe: str,
    limit: int = 200,
) -> tuple[list, int]:
    """Query PolicyApplyEvent for /audit?event_source=policy_apply.

    Uses the ``ix_policy_apply_result_ts`` composite index implicitly via the
    ``ORDER BY ts DESC`` clause (SQLite picks the index by ts). Filters mirror
    the tool_use path: machine_id substring + timeframe window.
    """
    from ccguard.server.db.models import PolicyApplyEvent

    hours = _TIMEFRAME_HOURS.get(timeframe, 24)
    cutoff = datetime.now(UTC) - timedelta(hours=hours)
    stmt = select(PolicyApplyEvent).where(PolicyApplyEvent.ts >= cutoff)  # type: ignore[arg-type]
    if machine_id_like:
        stmt = stmt.where(
            PolicyApplyEvent.machine_id.like(f"%{machine_id_like}%")  # type: ignore[attr-defined]
        )
    stmt = stmt.order_by(PolicyApplyEvent.ts.desc())  # type: ignore[attr-defined]
    rows = list(session.exec(stmt.limit(limit)))
    total = len(rows)  # adequate for v0.2 admin UI; matches list_events shape
    return rows, total


@router.get("/audit", response_class=HTMLResponse)
def audit_page(
    request: Request,
    machine_id: str = "",
    tool_name: str = "",
    decision: str = "",
    timeframe: str = "24h",
    event_source: str = "",
    user: str = Depends(require_session),
    session: Session = Depends(get_session),
) -> HTMLResponse:
    from ccguard.server.services.tool_use_service import list_events, timeline_buckets

    if decision not in ("allow", "deny", "error", ""):
        decision = ""
    if timeframe not in ("1h", "24h", "7d"):
        timeframe = "24h"
    # Whitelist event_source; anything other than "policy_apply" → default
    # tool_use branch (preserves v0.1 byte-equality).
    if event_source != "policy_apply":
        event_source = ""

    if event_source == "policy_apply":
        events, total = _policy_apply_events(
            session,
            machine_id_like=machine_id or None,
            timeframe=timeframe,
            limit=200,
        )
        buckets: list = []
        max_count = 0
    else:
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
            "event_source": event_source,
            "result_column_visible": event_source == "policy_apply",
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


_MANDATORY_SECTION_TEMPLATES = {
    "required_mcp_servers": "components/_mandatory_row_required_mcp_servers.html",
    "required_skills": "components/_mandatory_row_required_skills.html",
    "required_agents": "components/_mandatory_row_required_agents.html",
    "managed_claude_md_blocks": "components/_mandatory_row_managed_claude_md_blocks.html",
}


def _build_mandatory_sections_view(policy_obj) -> dict[str, list[dict]]:
    """Convert Policy.required_* / .managed_claude_md_blocks into template-friendly dicts.

    For ``required_mcp_servers``, pre-serializes ``env`` to a JSON string
    (``env_text``) and ``args`` to a newline-joined string (``args_text``)
    so the row partial can render them in a textarea (WR-07: one-per-line
    so an argument value can contain a literal comma).
    """
    out: dict[str, list[dict]] = {
        "required_mcp_servers": [],
        "required_skills": [],
        "required_agents": [],
        "managed_claude_md_blocks": [],
    }
    for s in getattr(policy_obj, "required_mcp_servers", []) or []:
        d = s.model_dump(mode="json", by_alias=True)
        d["args_text"] = "\n".join(d.get("args") or [])
        d["env_text"] = json.dumps(d.get("env") or {}, ensure_ascii=False)
        out["required_mcp_servers"].append(d)
    for s in getattr(policy_obj, "required_skills", []) or []:
        out["required_skills"].append(s.model_dump(mode="json"))
    for s in getattr(policy_obj, "required_agents", []) or []:
        out["required_agents"].append(s.model_dump(mode="json"))
    for s in getattr(policy_obj, "managed_claude_md_blocks", []) or []:
        out["managed_claude_md_blocks"].append(s.model_dump(mode="json"))
    return out


def _policy_with_pi_form_overrides(session: Session, form: dict[str, str]):
    """Build a Policy with the submitted prompt_injection.* values overlaid.

    Used by the /policy re-render path when ``_parse_prompt_injection`` raises:
    we want the textarea to keep showing the admin's offending input (including
    the bad regex) so they can fix the line in place. Non-PI sections come from
    the current published/draft policy unchanged.

    The PI section is rebuilt manually here (NOT via ``_parse_prompt_injection``,
    which would re-raise on the same input). We bypass validation so the
    template renders the raw values as-is.
    """
    from ccguard.server.services.policy_service import (
        get_current_published,
        get_draft,
        validate_yaml,
    )
    from ccguard.schemas.policy import LlamaGuardConfig, PromptInjectionConfig

    current = get_current_published(session)
    draft = get_draft(session)
    source = draft if draft is not None else current
    if source is None:
        raise HTTPException(status_code=503, detail="no policy in DB")
    policy_obj = validate_yaml(source.yaml_text)

    # Split textareas into lists preserving the offending raw lines (do NOT
    # strip empties so the admin sees their exact input).
    def _raw_lines(raw: str) -> list[str]:
        return [ln for ln in raw.splitlines() if ln.strip()]

    raw_severity = form.get("prompt_injection.severity", policy_obj.prompt_injection.severity)
    # Only allow valid enum into the model; if invalid (bad-severity test) fall
    # back to current value so PromptInjectionConfig validates.
    if raw_severity not in ("info", "warn", "block"):
        severity_for_model = policy_obj.prompt_injection.severity
    else:
        severity_for_model = raw_severity

    raw_endpoint = form.get(
        "prompt_injection.llama_guard.endpoint",
        policy_obj.prompt_injection.llama_guard.endpoint,
    ).strip() or "http://localhost:11434"

    raw_timeout_str = form.get("prompt_injection.llama_guard.timeout_ms", "")
    try:
        raw_timeout = int(raw_timeout_str)
        # CR-04: upper bound clamped 10000→200ms to match LlamaGuardConfig schema.
        if not (50 <= raw_timeout <= 200):
            raw_timeout = policy_obj.prompt_injection.llama_guard.timeout_ms
    except (ValueError, TypeError):
        raw_timeout = policy_obj.prompt_injection.llama_guard.timeout_ms

    policy_obj.prompt_injection = PromptInjectionConfig(
        enabled=form.get("prompt_injection.enabled", "") == "1",
        severity=severity_for_model,
        regex_patterns=_raw_lines(form.get("prompt_injection.regex_patterns", "")),
        allowlist_patterns=_raw_lines(form.get("prompt_injection.allowlist_patterns", "")),
        llama_guard=LlamaGuardConfig(
            enabled=form.get("prompt_injection.llama_guard.enabled", "") == "1",
            endpoint=raw_endpoint,
            timeout_ms=raw_timeout,
        ),
    )
    return policy_obj


def _render_rules_page(
    request: Request,
    *,
    user: str,
    session: Session,
    errors: dict[str, str] | None = None,
    policy_override=None,
    status_code: int = 200,
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
    policy_obj = policy_override if policy_override is not None else validate_yaml(source.yaml_text)
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
            "active_tab": "rules",
            "errors": errors or {},
        },
        status_code=status_code,
    )


@router.get("/policy", response_class=HTMLResponse)
def policy_editor(
    request: Request,
    user: str = Depends(require_session),
    session: Session = Depends(get_session),
) -> HTMLResponse:
    return _render_rules_page(request, user=user, session=session)


def _render_mandatory_page(
    request: Request,
    *,
    user: str,
    session: Session,
    errors: dict[str, str] | None = None,
    sections_override: dict[str, list[dict]] | None = None,
    status_code: int = 200,
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
    sections = sections_override or _build_mandatory_sections_view(policy_obj)
    return templates.TemplateResponse(
        request,
        "policy_editor_mandatory.html",
        {
            "user": user,
            "sections": sections,
            "errors": errors or {},
            "current_rev": current.revision if current else "-",
            "draft_rev": draft.revision if draft else (current.revision + 1 if current else 1),
            "has_draft": draft is not None,
            "diff_lines": diff_lines,
            "csrf_token": _csrf_for(request),
            "active_tab": "mandatory",
        },
        status_code=status_code,
    )


@router.get("/policy/mandatory", response_class=HTMLResponse)
def policy_mandatory_editor(
    request: Request,
    user: str = Depends(require_session),
    session: Session = Depends(get_session),
) -> HTMLResponse:
    return _render_mandatory_page(request, user=user, session=session)


@router.get("/policy/mandatory/_row", response_class=HTMLResponse)
def policy_mandatory_row(
    request: Request,
    section: str = "",
    i: int = 0,
    _user: str = Depends(require_session),
) -> HTMLResponse:
    template = _MANDATORY_SECTION_TEMPLATES.get(section)
    if template is None:
        raise HTTPException(status_code=404, detail="unknown section")
    # Empty `item` so the partial renders blank inputs; `i` indexes the form field.
    return templates.TemplateResponse(
        request, template, {"i": i, "item": {}},
    )


def _form_to_sections_view(form: dict[str, str]) -> dict[str, list[dict]]:
    """Reconstruct sections view from raw form values so re-renders preserve user input.

    Mirrors `_build_mandatory_sections_view` shape (with `args_text`/`env_text`).
    """
    from ccguard.server.web.policy_form import parse_indexed_list
    out: dict[str, list[dict]] = {
        "required_mcp_servers": [],
        "required_skills": [],
        "required_agents": [],
        "managed_claude_md_blocks": [],
    }
    for row in parse_indexed_list(form, "required_mcp_servers"):
        out["required_mcp_servers"].append(
            {
                "name": row.get("name", ""),
                "command": row.get("command", ""),
                "args_text": row.get("args", ""),
                "env_text": row.get("env", ""),
            }
        )
    for row in parse_indexed_list(form, "required_skills"):
        out["required_skills"].append(
            {
                "name": row.get("name", ""),
                "frontmatter_type": row.get("frontmatter_type", ""),
                "content": row.get("content", ""),
            }
        )
    for row in parse_indexed_list(form, "required_agents"):
        out["required_agents"].append(
            {"name": row.get("name", ""), "content": row.get("content", "")}
        )
    for row in parse_indexed_list(form, "managed_claude_md_blocks"):
        out["managed_claude_md_blocks"].append(
            {
                "id": row.get("id", ""),
                "description": row.get("description", ""),
                "content": row.get("content", ""),
            }
        )
    return out


@router.post("/policy/draft")
async def save_policy_draft(
    request: Request,
    user: str = Depends(require_session),
    _csrf: None = Depends(require_csrf),
    session: Session = Depends(get_session),
) -> Response:
    from ccguard.server.services.policy_service import (
        get_current_published,
        save_draft,
    )
    from ccguard.server.web.policy_form import (
        MandatorySectionError,
        PromptInjectionFormError,
        form_to_yaml,
    )

    form = await request.form()
    form_dict = dict(form)
    tab = form_dict.get("tab", "rules")
    if tab not in ("rules", "mandatory"):
        tab = "rules"
    current = get_current_published(session)
    current_rev = current.revision if current else 0
    baseline = yaml.safe_load(current.yaml_text) if current else None
    try:
        yaml_text = form_to_yaml(
            form_dict,
            current_revision=current_rev,
            baseline=baseline,
            tab=tab,
        )
    except MandatorySectionError as exc:
        # Re-render /policy/mandatory with the locked Russian error notice above
        # the offending card and preserve user input from the submitted form.
        return _render_mandatory_page(
            request,
            user=user,
            session=session,
            errors={exc.section: str(exc)},
            sections_override=_form_to_sections_view(form_dict),
            status_code=200,
        )
    except PromptInjectionFormError as exc:
        # Phase 5 / 05-05: re-render /policy with the Russian error notice atop
        # the Prompt-Injection card and preserve submitted PI form values so the
        # admin can fix the offending line without retyping everything.
        return _render_rules_page(
            request,
            user=user,
            session=session,
            errors={exc.section: str(exc)},
            policy_override=_policy_with_pi_form_overrides(session, form_dict),
            status_code=200,
        )
    except ValidationError as e:
        raise HTTPException(status_code=422, detail=str(e))
    save_draft(session, yaml_text=yaml_text, user_id=user)
    target = "/policy/mandatory" if tab == "mandatory" else "/policy"
    return RedirectResponse(url=target, status_code=303)


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
    from ccguard.server.web.policy_form import (
        PromptInjectionFormError,
        form_to_yaml,
    )

    form = await request.form()
    form_dict = dict(form)
    keys = list(form.keys())
    has_section_data = any(
        k.startswith(prefix + ".")
        for k in keys
        for prefix in (
            "mcp_servers",
            "network",
            "commands",
            "skills",
            "hooks",
            "agents",
            "env",
            # CR-02: PI-only submissions to /policy/publish previously bypassed
            # form_to_yaml entirely → silent data loss + skipped _redos_safe.
            "prompt_injection",
        )
    )
    if has_section_data:
        current = get_current_published(session)
        current_rev = current.revision if current else 0
        baseline = yaml.safe_load(current.yaml_text) if current else None
        try:
            yaml_text = form_to_yaml(
                form_dict, current_revision=current_rev, baseline=baseline,
            )
        except PromptInjectionFormError as exc:
            # CR-02: mirror /policy/draft UX — re-render the rules page with
            # the locked Russian notice atop the Prompt-Injection card
            # instead of raising 500.
            return _render_rules_page(
                request,
                user=user,
                session=session,
                errors={exc.section: str(exc)},
                policy_override=_policy_with_pi_form_overrides(session, form_dict),
                status_code=200,
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


def _settings_context(request: Request, session: Session, user: str) -> dict:
    """Build the shared template context for /settings GET + validation re-renders."""
    from ccguard.server.services.token_service import list_tokens
    from ccguard.server.services.settings_service import get_setting
    from ccguard.server.db.models import ScanResult

    from ccguard.server.services.settings_service import parse_budget

    cfg = _config(request)
    enabled = (get_setting(session, "llm_scanner_enabled") or "false").lower() == "true"
    budget = parse_budget(get_setting(session, "daily_call_budget"))
    scans = list(
        session.exec(
            select(ScanResult).order_by(ScanResult.scanned_at.desc()).limit(10)  # type: ignore[attr-defined]
        )
    )
    # initial-render values for the inline usage counter
    usage = _llm_usage_summary(session)
    return {
        "user": user,
        "tokens": list_tokens(session),
        "new_token": request.query_params.get("new_token"),
        "password_msg": request.query_params.get("password_msg"),
        "server_version": "0.1.0",
        "csrf_token": _csrf_for(request),
        "has_api_key": bool(cfg.anthropic_api_key),
        "llm_settings": {
            "llm_scanner_enabled": enabled,
            "daily_call_budget": budget,
        },
        "scans": scans,
        # variables consumed by the inline-included _llm_usage_counter.html
        "enabled": usage["enabled"],
        "used": usage["used"],
        "budget": usage["budget"],
        "cost_dollars": usage["cost_cents"] / 100.0,
    }


def _llm_usage_summary(session: Session) -> dict:
    """Synchronous version of ScanService.get_daily_usage for the admin UI.

    Avoids needing an event loop / async context inside the request handler.
    Mirrors :meth:`ScanService.get_daily_usage` shape exactly.
    """
    from datetime import UTC, datetime
    from ccguard.server.db.models import LLMCallLog
    from ccguard.server.services.settings_service import get_setting, parse_budget

    now = datetime.now(UTC)
    day_start = now.replace(hour=0, minute=0, second=0, microsecond=0)
    rows = list(session.exec(select(LLMCallLog).where(LLMCallLog.ts >= day_start)))
    enabled = (get_setting(session, "llm_scanner_enabled") or "false").lower() == "true"
    budget = parse_budget(get_setting(session, "daily_call_budget"))
    return {
        "used": len(rows),
        "budget": budget,
        "cost_cents": sum(r.cost_estimate_cents for r in rows),
        "enabled": enabled,
    }


@router.get("/settings", response_class=HTMLResponse)
def settings_page(
    request: Request,
    user: str = Depends(require_session),
    session: Session = Depends(get_session),
) -> HTMLResponse:
    ctx = _settings_context(request, session, user)
    return templates.TemplateResponse(request, "settings.html", ctx)


@router.post("/admin/llm-settings")
def admin_llm_settings_save(
    request: Request,
    daily_call_budget: str = Form(""),
    enabled: str = Form(""),
    user: str = Depends(require_session),
    _csrf: None = Depends(require_csrf),
    session: Session = Depends(get_session),
) -> Response:
    """Persist Settings.llm_scanner_enabled + daily_call_budget.

    Validation: 0 ≤ daily_call_budget ≤ 10000. On invalid input → 200 with
    re-rendered /settings template + locked Russian validation message.
    """
    from ccguard.server.services.settings_service import set_setting

    try:
        budget_int = int(daily_call_budget)
    except (TypeError, ValueError):
        budget_int = -1
    if budget_int < 0 or budget_int > 10000:
        ctx = _settings_context(request, session, user)
        ctx["validation_error"] = "Бюджет должен быть целым числом от 0 до 10000."
        return templates.TemplateResponse(request, "settings.html", ctx, status_code=200)

    # Checkbox semantics: present → "true"; absent → "false". FastAPI's Form
    # default for an unchecked checkbox is the empty string (because the
    # browser does not include the input at all). Any non-empty value means
    # the box was checked (HTML always sends "on" unless overridden).
    set_setting(session, "llm_scanner_enabled", "true" if enabled else "false")
    set_setting(session, "daily_call_budget", str(budget_int))
    return RedirectResponse(url="/settings", status_code=303)


@router.post("/admin/scan/{file_hash}/rescan", response_class=HTMLResponse)
def admin_scan_rescan(
    request: Request,
    file_hash: str,
    user: str = Depends(require_session),
    _csrf: None = Depends(require_csrf),
    session: Session = Depends(get_session),
) -> HTMLResponse:
    """Per-row re-scan endpoint (HTMX outerHTML swap).

    Path validation: ``file_hash`` must be 64-char lowercase hex (sha256). The
    server does not store content (D-02), so we only invalidate the cache TTL
    and return the existing finding row partial. The next agent inventory
    cycle will trigger the real re-scan. Inline notices surface budget /
    disabled states without raising — HTMX gets a valid <tr> either way.
    """
    from ccguard.server.db.models import FindingRecord, ScanResult
    from datetime import UTC, datetime, timedelta

    if len(file_hash) != 64 or any(c not in "0123456789abcdef" for c in file_hash):
        raise HTTPException(status_code=404, detail="invalid file_hash")

    scan_row = session.exec(
        select(ScanResult).where(ScanResult.file_hash == file_hash)
    ).one_or_none()
    if scan_row is None:
        raise HTTPException(status_code=404, detail="unknown file_hash")

    # Invalidate cache TTL — next agent cycle re-scans.
    scan_row.ttl_expires_at = datetime.now(UTC) - timedelta(seconds=1)
    session.add(scan_row)
    session.commit()

    # Pull the latest finding row for this file_hash for the partial render.
    finding_row = session.exec(
        select(FindingRecord)
        .where(FindingRecord.rule_id.like("llm.scan.%"))  # type: ignore[attr-defined]
        .order_by(FindingRecord.discovered_at.desc())  # type: ignore[attr-defined]
    ).first()
    # Filter by file_hash in-process (payload_json is JSON text — keep the SQL
    # simple and let the python side filter).
    target = None
    cands = session.exec(
        select(FindingRecord)
        .where(FindingRecord.rule_id.like("llm.scan.%"))  # type: ignore[attr-defined]
        .order_by(FindingRecord.discovered_at.desc())  # type: ignore[attr-defined]
        .limit(50)
    )
    for r in cands:
        try:
            payload = json.loads(r.payload_json) if r.payload_json else {}
        except (ValueError, TypeError):
            payload = {}
        if isinstance(payload, dict) and payload.get("file_hash") == file_hash:
            target = r
            break
    if target is None:
        target = finding_row  # last-resort fallback; should not normally happen

    usage = _llm_usage_summary(session)
    notice: str | None = None
    if not usage["enabled"]:
        notice = "scanner_disabled"
    elif usage["budget"] == 0:
        # WR-01: budget=0 with scanner enabled is a distinct admin-mistake
        # state, not "exhausted today". Surface a different notice so the
        # operator knows to raise the limit on /settings.
        notice = "budget_zero"
    elif usage["used"] >= usage["budget"]:
        notice = "budget_exhausted"

    vm = _finding_view_model(target) if target is not None else None
    return templates.TemplateResponse(
        request,
        "components/_finding_row.html",
        {
            "finding": vm,
            "rescan_notice": notice,
            "csrf_token": _csrf_for(request),
        },
    )


@router.post("/admin/scan/rescan-all")
def admin_scan_rescan_all(
    request: Request,
    _user: str = Depends(require_session),
    _csrf: None = Depends(require_csrf),
    session: Session = Depends(get_session),
) -> RedirectResponse:
    """Enqueue a one-shot APScheduler job that expires every ScanResult TTL.

    Per D-03: agent's next inventory cycle repopulates the cache. We never
    re-scan from the server because we never store content.
    """
    from ccguard.server.scheduler import enqueue_rescan_all

    scheduler = getattr(request.app.state, "scheduler", None)
    engine = request.app.state.engine
    enqueue_rescan_all(scheduler, engine)
    return RedirectResponse(url="/settings", status_code=303)


@router.get("/_partials/settings/llm-usage", response_class=HTMLResponse)
def llm_usage_partial(
    request: Request,
    _user: str = Depends(require_session),
    session: Session = Depends(get_session),
) -> HTMLResponse:
    """HTMX-polled (every 30s) usage strip for the LLM-сканер settings card."""
    usage = _llm_usage_summary(session)
    return templates.TemplateResponse(
        request,
        "components/_llm_usage_counter.html",
        {
            "enabled": usage["enabled"],
            "used": usage["used"],
            "budget": usage["budget"],
            "cost_dollars": usage["cost_cents"] / 100.0,
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
    from ccguard.server.db.models import FindingRecord, Machine, MachineBaseline
    from ccguard.server.services.anomaly_constants import VALID_METRICS, rule_id_for

    if metric not in VALID_METRICS:
        raise HTTPException(status_code=404, detail="unknown metric")

    # WR-04: mirror machine_detail's 404 — previously any URL like
    # /anomalies/totally-fake-id/bash_calls_per_day rendered the warm-up page,
    # which is enumeration-friendly and inconsistent with the rest of the UI.
    if session.get(Machine, machine_id) is None:
        raise HTTPException(status_code=404, detail="unknown machine")

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
    # WR-07: validate the JSON shape — recent_points_json must decode to a
    # list of numbers. A non-list shape (``null``, ``{}``, etc.) or a
    # non-numeric / NaN entry is treated as no-data so downstream ``max()``
    # and template formatting never see corrupt values.
    raw_points = _parse_recent_points(baseline.recent_points_json if baseline else None)

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


def _parse_recent_points(payload: str | None, *, pad: bool = True) -> list[float]:
    """Validate and parse a ``MachineBaseline.recent_points_json`` string.

    WR-07: a malformed or non-list payload must NOT crash the route. Returns:

    * ``pad=True``  → a 14-length list of floats (left-padded with zeros);
    * ``pad=False`` → the validated list as-is (may be shorter than 14).

    Non-list shapes (``null``, ``{}``), non-numeric entries, and ``NaN``
    values are dropped so downstream ``max()`` and template formatting never
    see corrupt values.
    """
    if not payload:
        return [0.0] * 14 if pad else []
    try:
        raw = json.loads(payload)
    except (ValueError, TypeError):
        return [0.0] * 14 if pad else []
    if not isinstance(raw, list):
        return [0.0] * 14 if pad else []
    out: list[float] = []
    for v in raw:
        if isinstance(v, bool):
            # bool is a subclass of int — exclude explicitly.
            continue
        if not isinstance(v, (int, float)):
            continue
        fv = float(v)
        if math.isnan(fv):
            continue
        out.append(fv)
    if pad:
        if len(out) < 14:
            out = [0.0] * (14 - len(out)) + out
        else:
            out = out[-14:]
    return out


def _build_sparkline_cell(baseline, labels: list[str]) -> dict:
    """Build the per-cell sparkline view-model (warm-up or 14 bars).

    Cell shape (consumed by components/_anomalies_matrix.html):
      {warmup: bool, points: [{value, height_pct, label}], last_value, is_outlier}
    """
    if baseline is None or not baseline.baseline_ready:
        return {"warmup": True, "points": [], "last_value": None, "is_outlier": False}
    # WR-07: validate JSON shape — non-list or non-numeric entries become
    # no-data (warm-up render) instead of raising TypeError downstream.
    raw = _parse_recent_points(baseline.recent_points_json, pad=False)
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
