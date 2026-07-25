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


def _ru_plural(n: int, one: str, few: str, many: str) -> str:
    """Russian plural picker: one/few/many forms."""
    n = abs(int(n))
    last_two = n % 100
    if 11 <= last_two <= 14:
        return many
    last = n % 10
    if last == 1:
        return one
    if 2 <= last <= 4:
        return few
    return many


def _hook_word(n: int) -> str:
    return _ru_plural(n, "хук", "хука", "хуков")


def _skill_word(n: int) -> str:
    return _ru_plural(n, "скилл", "скилла", "скиллов")


def _agent_word(n: int) -> str:
    return _ru_plural(n, "агент", "агента", "агентов")


templates.env.filters["hook_word"] = _hook_word
templates.env.filters["skill_word"] = _skill_word
templates.env.filters["agent_word"] = _agent_word

from ccguard.server.web.finding_view import humanize_rule as _humanize_rule

templates.env.globals["humanize_rule"] = _humanize_rule

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
    from ccguard.server.db.models import FindingRecord, ProposedSignal
    from ccguard.server.services.fleet_risk import compute_fleet_risk
    from ccguard.server.services.machine_service import list_machines_with_status
    from ccguard.server.services.settings_service import get_enforcement_mode
    from ccguard.server.services.dangerous_findings import todays_blocked_count
    from ccguard.server.services.surface_score_service import compute_surface_score
    machines = list_machines_with_status(session)
    fleet_risk = compute_fleet_risk(session, limit=10)
    enforcement_mode = get_enforcement_mode(session)
    dangerous_today = todays_blocked_count(session)
    # Дашборд-KPI (read-only): скоринг поверхности + счётчики.
    surface = compute_surface_score(session)
    since7 = datetime.now(UTC) - timedelta(days=7)
    week_detections = len(
        session.exec(select(FindingRecord.id).where(FindingRecord.discovered_at >= since7)).all()
    )
    open_threat_rows = session.exec(
        select(FindingRecord)
        .where(FindingRecord.severity.in_(["block", "critical"]))
        .where(FindingRecord.discovered_at >= since7)
        .order_by(FindingRecord.discovered_at.desc())
    ).all()
    open_threats = len(open_threat_rows)
    # Surface the actual catch on the landing (not just a count): the most recent
    # block/critical findings with a plain-language label + machine link. The
    # "ioa.*" correlations (incl. the moat) sort first — they are the story.
    from ccguard.server.web.finding_view import humanize_rule
    _sorted = sorted(
        open_threat_rows,
        key=lambda f: (0 if f.rule_id.startswith("ioa.") else 1, ),
    )
    active_threats = [
        {
            "id": f.id,
            "machine_id": f.machine_id,
            "severity": f.severity,
            "rule_id": f.rule_id,
            "label": humanize_rule(f.rule_id),
            "discovered_at": f.discovered_at,
            "is_moat": f.rule_id == "ioa.ai_trigger_escalation",
        }
        for f in _sorted[:8]
    ]
    pending_feeds = len(
        session.exec(select(ProposedSignal.id).where(ProposedSignal.status == "pending")).all()
    )
    # Личность агента: на скольких машинах агент работает БЕЗ подтверждений
    # человеком. Первый вопрос руководителя ИБ, поэтому место — на главной.
    from ccguard.server.services.identity_service import fleet_permission_summary
    identity = fleet_permission_summary(session)
    return templates.TemplateResponse(
        request,
        "overview.html",
        {
            "user": user,
            "machines": machines,
            "fleet_risk": fleet_risk,
            "enforcement_mode": enforcement_mode,
            "dangerous_today": dangerous_today,
            "surface": surface,
            "week_detections": week_detections,
            "open_threats": open_threats,
            "active_threats": active_threats,
            "pending_feeds": pending_feeds,
            "identity": identity,
            "csrf_token": _csrf_for(request),
        },
    )


@router.get("/coverage", response_class=HTMLResponse)
def coverage_page(
    request: Request,
    user: str = Depends(require_session),
    session: Session = Depends(get_session),
) -> HTMLResponse:
    """Карта покрытия (ТЗ-08): техники трёх фреймворков по стадиям kill-chain.

    Каждая техника несёт ЧЕМ она покрыта (детектор-ключи + артефакт-индикаторы +
    тип контроля), сгруппирована по стадии в порядке kill-chain — чтобы было видно
    конкретно ЧТО и КАК мы ловим, а не безымянные точки. Read-only над
    coverage_service, детект-движки/БД не трогаем.
    """
    from ccguard.server.db.models import (
        Detector,
        DetectorTechniqueMapping,
        IndicatorTechniqueMapping,
        Technique,
        ThreatIndicator,
    )
    from ccguard.server.services import coverage_service
    from ccguard.server.services.chain_constants import stage_rank

    techs = session.exec(select(Technique)).all()
    covered_ids = {t.technique_id for t in coverage_service.techniques_covered(session)}
    by_control = coverage_service.coverage_by_control_type(session)
    # P6: detection REALITY per technique — detecting / dark / armed — so a
    # registered-but-never-fired detector reads honestly instead of a blind
    # green badge. Keyed by technique_id; absent for indicator-only techniques.
    detection_status = coverage_service.technique_detection_status(session)

    # mechanism index: technique_id -> {detectors, indicators, controls}
    mech: dict[str, dict] = {}

    def _slot(tid: str) -> dict:
        return mech.setdefault(tid, {"detectors": set(), "indicators": 0, "controls": set()})

    for tid, dkey, ct in session.exec(
        select(
            DetectorTechniqueMapping.technique_id,
            Detector.detector_key,
            DetectorTechniqueMapping.control_type,
        ).join(Detector, Detector.detector_key == DetectorTechniqueMapping.detector_key)
    ).all():
        slot = _slot(tid)
        slot["detectors"].add(dkey)
        slot["controls"].add(ct)
    for tid, ct in session.exec(
        select(IndicatorTechniqueMapping.technique_id, IndicatorTechniqueMapping.control_type)
        .join(ThreatIndicator, ThreatIndicator.id == IndicatorTechniqueMapping.indicator_id)
        .where(ThreatIndicator.enabled == True)  # noqa: E712
        .where(ThreatIndicator.status == "active")
    ).all():
        slot = _slot(tid)
        slot["indicators"] += 1
        slot["controls"].add(ct)

    # parent rollup: a covered sub-technique makes its parent covered "← child".
    direct_ids = set(mech.keys())
    rollup: dict[str, set] = {}
    for t in techs:
        if t.parent_technique and t.technique_id in direct_ids:
            rollup.setdefault(t.parent_technique, set()).add(t.technique_id)

    def _klass(controls: list[str]) -> str:
        for key in ("PREV", "DETECT", "SCOPE", "GATE", "ISOLATE"):
            if key in controls:
                return {"PREV": "c-prev", "DETECT": "c-detect"}.get(key, "c-scope")
        return "c-detect"

    def _tv(t: Technique) -> dict:
        slot = mech.get(t.technique_id, {"detectors": set(), "indicators": 0, "controls": set()})
        via = sorted(rollup.get(t.technique_id, set()))
        parts = sorted(slot["detectors"])
        if slot["indicators"]:
            parts.append(f"артефакт ×{slot['indicators']}")
        if not parts and via:
            parts = ["← " + ", ".join(via)]
        controls = sorted(slot["controls"])
        return {
            "id": t.technique_id,
            "fw": t.framework,
            "name": t.name,
            "tactic": t.tactic,
            "covered": t.technique_id in covered_ids,
            "mech": " · ".join(parts),
            "controls": controls,
            "klass": _klass(controls),
            "detection_status": detection_status.get(t.technique_id),
        }

    # group in-scope techniques into kill-chain stages
    stage_map: dict[str, list[Technique]] = {}
    for t in techs:
        if t.in_scope:
            stage_map.setdefault(t.tactic, []).append(t)

    stages: list[dict] = []
    for tac in sorted(stage_map, key=lambda s: (stage_rank(s), s)):
        tvs = sorted(
            (_tv(t) for t in stage_map[tac]),
            key=lambda x: (not x["covered"], x["id"]),
        )
        c = sum(1 for x in tvs if x["covered"])
        stages.append(
            {
                "tactic": tac,
                "covered": c,
                "total": len(tvs),
                "pct": round(100 * c / len(tvs)) if tvs else 0,
                "source": stage_map[tac][0].tactic_source,
                "techniques": tvs,
            }
        )

    oos = sorted(
        (_tv(t) for t in techs if not t.in_scope),
        key=lambda x: (stage_rank(x["tactic"]), x["id"]),
    )

    tot_c = sum(s["covered"] for s in stages)
    tot_t = sum(s["total"] for s in stages)
    overall = round(100 * tot_c / tot_t) if tot_t else 0

    control_cards = [
        {"key": "PREV", "label": "Блокируем до запуска", "count": by_control.get("PREV", 0), "cls": "prev"},
        {"key": "DETECT", "label": "Видим поведенчески", "count": by_control.get("DETECT", 0), "cls": "detect"},
        {"key": "SCOPE", "label": "Ограничиваем доступ", "count": by_control.get("SCOPE", 0), "cls": "scope"},
    ]

    return templates.TemplateResponse(
        request,
        "coverage_map.html",
        {
            "user": user,
            "csrf_token": _csrf_for(request),
            "stages": stages,
            "oos": oos,
            "overall": overall,
            "tot_covered": tot_c,
            "tot_total": tot_t,
            "gaps_count": tot_t - tot_c,
            "control_cards": control_cards,
        },
    )


@router.get("/coverage/{technique_id}", response_class=HTMLResponse)
def technique_detail_page(
    request: Request,
    technique_id: str,
    user: str = Depends(require_session),
    session: Session = Depends(get_session),
) -> HTMLResponse:
    """Детальная страница техники (drill-down с /coverage): описание +
    первоисточник, ЧЕМ и КАК ловим (детекторы/индикаторы + тип контроля),
    связанные техники (crosswalk), примеры атак (сценарии по стадии) и реальные
    публичные инциденты. Read-only над coverage_service."""
    from ccguard.server.db.models import Technique
    from ccguard.server.services import chain_seed_service, coverage_service
    from ccguard.server.services.transparency_content import incidents_for

    detail = coverage_service.coverage_detail(session, technique_id)
    if not detail.get("found"):
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="unknown technique")
    tech = session.exec(
        select(Technique).where(Technique.technique_id == technique_id)
    ).first()

    cross: list[dict] = []
    if detail.get("crosswalk"):
        for rel in session.exec(
            select(Technique).where(Technique.technique_id.in_(detail["crosswalk"]))
        ).all():
            cross.append({"id": rel.technique_id, "fw": rel.framework,
                          "name": rel.name, "tactic": rel.tactic})
        cross.sort(key=lambda x: x["id"])

    scenarios = chain_seed_service.list_scenarios(session)
    example_scenarios = [
        s for s in scenarios if any(st["tactic"] == tech.tactic for st in s["steps"])
    ]

    return templates.TemplateResponse(
        request,
        "technique_detail.html",
        {
            "user": user,
            "csrf_token": _csrf_for(request),
            "t": {
                "id": tech.technique_id, "fw": tech.framework, "name": tech.name,
                "tactic": tech.tactic, "tactic_source": tech.tactic_source,
                "description": tech.description, "url": tech.url,
                "in_scope": tech.in_scope, "covered": detail["covered"],
                "control_types": detail["control_types"],
            },
            "detectors": detail["detectors"],
            "indicators": detail["indicators"],
            "covered_via_rollup": detail.get("covered_via_rollup"),
            "covered_by_children": detail.get("covered_by_children", []),
            "crosswalk": cross,
            "example_scenarios": example_scenarios,
            "incidents": incidents_for(technique_id),
        },
    )


@router.get("/detectors/{detector_key}", response_class=HTMLResponse)
def detector_detail_page(
    request: Request,
    detector_key: str,
    user: str = Depends(require_session),
    session: Session = Depends(get_session),
) -> HTMLResponse:
    """Детальная страница детектора/корреляции: что наблюдает, какие сигналы,
    окно корреляции, что считается срабатыванием, какие техники покрывает."""
    from ccguard.server.db.models import Detector, DetectorTechniqueMapping, Technique
    from ccguard.server.services.transparency_content import detector_detail

    det = session.exec(
        select(Detector).where(Detector.detector_key == detector_key)
    ).first()
    if det is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="unknown detector")

    maps = session.exec(
        select(DetectorTechniqueMapping).where(
            DetectorTechniqueMapping.detector_key == detector_key
        )
    ).all()
    by_ct = {m.technique_id: m.control_type for m in maps}
    techs: list[dict] = []
    if by_ct:
        for t in session.exec(
            select(Technique).where(Technique.technique_id.in_(list(by_ct)))
        ).all():
            techs.append({"id": t.technique_id, "fw": t.framework, "name": t.name,
                          "tactic": t.tactic, "control_type": by_ct.get(t.technique_id)})
        techs.sort(key=lambda x: x["id"])

    return templates.TemplateResponse(
        request,
        "detector_detail.html",
        {
            "user": user,
            "csrf_token": _csrf_for(request),
            "d": {
                "key": det.detector_key, "name": det.name, "kind": det.kind,
                "description": det.description,
                "rule_ids": [r for r in (det.rule_ids or "").split(",") if r],
            },
            "explain": detector_detail(detector_key),
            "techniques": techs,
        },
    )


@router.get("/correlations", response_class=HTMLResponse)
def correlations_page(
    request: Request,
    user: str = Depends(require_session),
    session: Session = Depends(get_session),
) -> HTMLResponse:
    """Реестр корреляционных детекторов (ТЗ-08) + их привязки к техникам."""
    from ccguard.server.db.models import Detector, DetectorTechniqueMapping

    detectors = session.exec(select(Detector).order_by(Detector.detector_key)).all()
    maps = session.exec(select(DetectorTechniqueMapping)).all()
    by_det: dict[str, list[dict]] = {}
    for m in maps:
        by_det.setdefault(m.detector_key, []).append({
            "technique_id": m.technique_id, "framework": m.framework,
            "control_type": m.control_type, "relevance": m.relevance,
        })
    items = [{
        "key": d.detector_key, "name": d.name, "kind": d.kind,
        "rule_ids": [r for r in (d.rule_ids or "").split(",") if r],
        "description": d.description,
        "bindings": sorted(by_det.get(d.detector_key, []), key=lambda x: (x["relevance"], x["technique_id"])),
    } for d in detectors]
    return templates.TemplateResponse(
        request, "correlations.html",
        {"user": user, "csrf_token": _csrf_for(request), "detectors": items},
    )


# Порядок категорий + человекочитаемые метаданные для каталога сигналов.
# key -> (заголовок, короткое пояснение, icon-ключ из indicators.html).
_SIGNAL_CATEGORY_META: dict[str, tuple[str, str, str]] = {
    "cred": ("Доступ к секретам", "чтение ключей, токенов и учётных данных на диске / в env", "key"),
    "egress": ("Исходящий трафик · вынос", "инструменты и каналы отправки данных наружу", "globe"),
    "exec": ("Подозрительное исполнение", "пайп в шелл, деобфускация, LOLBin-побеги, inline-код", "terminal"),
    "persist": ("Закрепление", "автозапуск, cron/systemd/launchd, ключи, git-хуки, IAM", "key"),
    "discovery": ("Разведка", "инвентаризация хоста, сети, аккаунтов, путей эскалации", "globe"),
    "defense": ("Сокрытие следов", "отключение защиты, чистка истории и логов, маскировка", "terminal"),
    "c2": ("Командный канал (C2)", "reverse shell и исходящие туннели удалённого управления", "globe"),
    "lateral": ("Боковое перемещение", "исполнение команд на других хостах", "globe"),
    "collection": ("Сбор данных", "стадирование архивов, снимки экрана, буфер, дампы БД", "key"),
    "impact": ("Разрушение", "майнинг, вайп дисков, удаление бэкапов, деструктивные операции", "terminal"),
    "container": ("Контейнеры · escape", "примитивы побега из контейнера, привилегированные поды", "terminal"),
    "pkg": ("Цепочка поставок", "публикация и установка пакетов из недоверенных источников", "globe"),
    "ai": ("Отравление AI-контекста", "внедрение инструкций в файлы-авторитеты агента", "terminal"),
    "fs": ("Запись на диск", "стадирование данных; маркеры кэша/VCS гасят ложные срабатывания", "key"),
    "content": ("Чтение внешнего", "получение недоверенного контента (web / внешний путь)", "globe"),
    "system": ("Привилегии · система", "chmod/setuid, sudo-эскалация, правка hosts", "terminal"),
    "cloud": ("Облачный вынос", "запись в облачное хранилище как канал эксфильтрации", "globe"),
    "recon": ("Разведка облака", "доступ к metadata-эндпоинту инстанса", "globe"),
    "config": ("Тамперинг конфигурации", "правка настроек AI-агента / MCP", "terminal"),
}


@router.get("/signals", response_class=HTMLResponse)
def signals_catalog_page(
    request: Request,
    user: str = Depends(require_session),
    session: Session = Depends(get_session),
) -> HTMLResponse:
    """Каталог поведенческих сигналов (Behavioral Detection, Stage 1).

    Read-only витрина встроенного ``CATALOG`` из agent-сенсора: каждый сигнал —
    per-event regex с привязкой к ATT&CK / ATLAS-технике. UI раньше показывал
    сигналы только по месту (в находках / панели риска); эта страница —
    browsable-каталог всех детекций-«входов» поведенческого слоя.
    """
    from ccguard.agent.signals.catalog import CATALOG

    grouped: dict[str, list[dict]] = {}
    for sig in CATALOG:
        cat = sig.id.split(".")[0]
        grouped.setdefault(cat, []).append({
            "id": sig.id,
            "technique": sig.attack_technique,
            "description": sig.description,
            "pattern": sig.pattern.pattern,
        })

    # Категории в осмысленном порядке kill-chain; неизвестные (на случай новых
    # префиксов) идут в конце по алфавиту.
    ordered_keys = [k for k in _SIGNAL_CATEGORY_META if k in grouped]
    ordered_keys += sorted(k for k in grouped if k not in _SIGNAL_CATEGORY_META)

    groups: list[dict] = []
    for key in ordered_keys:
        label, desc, icon = _SIGNAL_CATEGORY_META.get(key, (key, "", "dot"))
        rows = sorted(grouped[key], key=lambda r: r["id"])
        groups.append({
            "key": key,
            "label": label,
            "desc": desc,
            "icon": icon,
            "count": len(rows),
            "rows": rows,
        })

    from ccguard.server.services.coverage_service import known_technique_ids

    return templates.TemplateResponse(
        request, "signals_catalog.html",
        {
            "user": user,
            "csrf_token": _csrf_for(request),
            "groups": groups,
            "total": len(CATALOG),
            "cat_count": len(groups),
            "covered_techniques": known_technique_ids(session),
        },
    )


@router.get("/finding-rules", response_class=HTMLResponse)
def finding_rules_page(
    request: Request,
    user: str = Depends(require_session),
    session: Session = Depends(get_session),
) -> HTMLResponse:
    """Каталог правил-находок (rule_id registry) — витрина-компаньон к /signals.

    Показывает КАЖДЫЙ rule_id, который порождают движки: находки (FindingRecord,
    видны на /findings) и enforce-решения (PreToolUse, только в audit.log),
    сгруппированные по движку-источнику с серьёзностью. Read-only над курируемым
    реестром ``finding_rules_catalog`` — движки не трогаются.
    """
    from ccguard.server.services.finding_rules_catalog import CATALOG, catalog_grouped

    groups = catalog_grouped()
    findings_total = sum(1 for r in CATALOG if r.kind == "finding")
    decisions_total = sum(1 for r in CATALOG if r.kind == "decision")
    return templates.TemplateResponse(
        request, "finding_rules_catalog.html",
        {
            "user": user,
            "csrf_token": _csrf_for(request),
            "groups": groups,
            "total": len(CATALOG),
            "findings_total": findings_total,
            "decisions_total": decisions_total,
            "cat_count": len(groups),
        },
    )


@router.get("/indicators", response_class=HTMLResponse)
def indicators_page(
    request: Request,
    user: str = Depends(require_session),
    session: Session = Depends(get_session),
) -> HTMLResponse:
    """Каталог индикаторов (ТЗ-05/06): артефакт-правила, сгруппированные по типу
    и атрибутированные к техникам — вместо одного плоского списка."""
    from ccguard.server.db.models import ThreatIndicator

    # Humanized type metadata; raw key kept in output for filter + tests.
    type_meta = {
        "sensitive_path": ("Чувствительные пути", "секреты, ключи и креды на диске — чтение = credential-access", "key"),
        "dangerous_command": ("Опасные команды", "деструктивные и эксфильтрационные команды оболочки", "terminal"),
        "suspicious_host": ("Подозрительные хосты", "known-bad и exfil-эндпоинты в сетевых вызовах", "globe"),
        "safe_path": ("Безопасные пути", "whitelist — гасит ложные срабатывания", "check"),
    }
    type_order = {"sensitive_path": 0, "dangerous_command": 1, "suspicious_host": 2, "safe_path": 9}

    rows = session.exec(
        select(ThreatIndicator).order_by(ThreatIndicator.indicator_type, ThreatIndicator.value)
    ).all()
    active = [r for r in rows if r.status == "active"]
    pending = [r for r in rows if r.status == "pending"]

    def _iv(r: object) -> dict:
        return {"id": r.id, "type": r.indicator_type, "value": r.value, "kind": r.value_kind,
                "source": r.source, "source_ref": r.source_ref, "technique": r.technique,
                "tactic": r.tactic, "weight": r.weight, "status": r.status,
                "description": r.description}

    grouped: dict[str, list[dict]] = {}
    for r in active:
        grouped.setdefault(r.indicator_type, []).append(_iv(r))

    groups: list[dict] = []
    for tkey in sorted(grouped, key=lambda k: (type_order.get(k, 5), k)):
        label, desc, icon = type_meta.get(tkey, (tkey.replace("_", " ").title(), "", "dot"))
        items = grouped[tkey]
        attributed = sum(1 for i in items if i["technique"])
        groups.append({
            "key": tkey, "label": label, "desc": desc, "icon": icon,
            "count": len(items), "attributed": attributed,
            "rows": sorted(items, key=lambda i: (-i["weight"], i["value"])),
        })

    from ccguard.server.services.coverage_service import known_technique_ids

    return templates.TemplateResponse(
        request, "indicators.html",
        {"user": user, "csrf_token": _csrf_for(request),
         "groups": groups, "pending": [_iv(r) for r in pending],
         "total": len(active), "type_count": len(groups),
         "covered_techniques": known_technique_ids(session)},
    )


@router.get("/attacks", response_class=HTMLResponse)
def attacks_page(
    request: Request,
    user: str = Depends(require_session),
    session: Session = Depends(get_session),
) -> HTMLResponse:
    """Цепочки-сценарии (ТЗ-09): стадии kill-chain как данные + недавние срабатывания."""
    from ccguard.server.db.models import ChainMatch
    from ccguard.server.services import chain_seed_service

    scenarios = chain_seed_service.list_scenarios(session)
    matches = session.exec(
        select(ChainMatch).order_by(ChainMatch.matched_at.desc()).limit(20)
    ).all()
    recent = [{
        "scenario_key": m.scenario_key, "machine_id": m.machine_id,
        "session_id": m.session_id, "matched_at": m.matched_at,
        "finding_id": m.finding_id,
        "steps": json.loads(m.matched_steps_json or "[]"),
    } for m in matches]
    return templates.TemplateResponse(
        request, "attacks.html",
        {"user": user, "csrf_token": _csrf_for(request),
         "scenarios": scenarios, "recent": recent},
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


@router.get("/admin/install-agent", response_class=HTMLResponse)
def install_agent_page(
    request: Request,
    user: str = Depends(require_session),
) -> HTMLResponse:
    """Static onboarding page: how to install the ccguard agent on a dev box.

    Linked from empty-state CTAs on /machines and / (overview) so a fresh
    instance has a clear next step instead of a silent dashboard.
    """
    return templates.TemplateResponse(
        request,
        "install_agent.html",
        {"user": user, "csrf_token": _csrf_for(request)},
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
    from ccguard.server.services import suppression_service
    from ccguard.server.services.risk_history import (
        get_risk_history_14d,
        get_user_scores_today,
    )
    from ccguard.server.web.finding_view import build_explainable_findings
    from ccguard.server.services import enforce_block_service, mcp_baseline_service
    from ccguard.server.services.network_findings import (
        recent_network_cards_for_machine,
    )
    from ccguard.server.services.pi_read_findings import (
        recent_pi_read_cards_for_machine,
    )
    from ccguard.server.services import sensor_diagnosis
    from ccguard.server.services import protection_incident_service
    from ccguard.server.db.models import MCPServerBaseline
    machine = session.get(Machine, machine_id)
    if machine is None:
        raise HTTPException(status_code=404)
    findings = get_findings_for_machine(session, machine_id)
    risk_series = get_risk_history_14d(session, machine_id)
    risk_max = max((p["score"] for p in risk_series), default=0.0)
    suppressions = suppression_service.list_for_machine(session, machine_id=machine_id)
    # D3: sync freshness badge — bucket + human label from last_seen.
    from ccguard.server.services._utc import aware_utc as _aware_utc
    _now_dt = datetime.now(UTC)
    _delta = _now_dt - _aware_utc(machine.last_seen)
    _mins = int(_delta.total_seconds() // 60)
    if _mins < 30:
        sync_freshness = {"bucket": "fresh", "label": f"{_mins} мин назад"}
    elif _mins < 24 * 60:
        sync_freshness = {"bucket": "stale", "label": f"{_mins // 60} ч назад"}
    else:
        sync_freshness = {"bucket": "missing", "label": f"{_mins // (24 * 60)} дн назад"}
    # Per-user attribution: top actors on this machine in the last 7 days.
    from ccguard.server.db.models import ToolUseEvent as _TUE
    from sqlalchemy import func as _func
    from datetime import timedelta as _td
    actor_rows = list(session.exec(
        select(_TUE.actor_user, _func.count().label("n"))  # type: ignore[arg-type]
        .where(_TUE.machine_id == machine_id)
        .where(_TUE.ts >= datetime.now(UTC) - _td(days=7))
        .where(_TUE.actor_user.is_not(None))  # type: ignore[attr-defined]
        .group_by(_TUE.actor_user)
        .order_by(_func.count().desc())
        .limit(10)
    ))
    user_score_map = {
        r["actor"]: {"score": r["score"], "top_signal": r["top_signal"]}
        for r in get_user_scores_today(session, machine_id=machine_id)
    }
    top_actors = []
    for r in actor_rows:
        actor = r[0]
        score_info = user_score_map.get(actor, {})
        top_actors.append({
            "actor": actor,
            "count": int(r[1]),
            "score": score_info.get("score", 0.0),
            "top_signal": score_info.get("top_signal"),
        })
    # MCP rug pull: load recent findings + baseline status map for this machine.
    rug_rows = mcp_baseline_service.list_recent_rug_pull_findings(
        session, machine_id, days=7
    )
    mcp_rug_cards: list[dict] = []
    for r in rug_rows:
        try:
            p = json.loads(r.payload_json)
        except (ValueError, TypeError):
            p = {}
        mcp_rug_cards.append({
            "rule_id": r.rule_id,
            "severity": r.severity,
            "discovered_at": r.discovered_at,
            "mcp_name": p.get("mcp_name") or p.get("matched_value") or "?",
            "title": p.get("title") or r.rule_id,
            "description": p.get("description") or "",
            "recommendation": p.get("recommendation") or "",
            "old_preview": p.get("old_preview"),
            "new_preview": p.get("new_preview"),
            "llm_verdict": p.get("llm_verdict"),
            "llm_rationale": p.get("llm_rationale"),
        })
    baseline_rows = list(session.exec(
        select(MCPServerBaseline).where(MCPServerBaseline.machine_id == machine_id)
    ))

    # Hook TOFU baseline: bootstrap banner + drift cards + status badges.
    from sqlalchemy import func as _hbf
    from ccguard.server.db.models import FindingRecord, HookBaseline
    pending_hook_count = session.exec(
        select(_hbf.count(HookBaseline.id)).where(
            HookBaseline.machine_id == machine_id,
            HookBaseline.status == "pending",
        )
    ).one()
    if isinstance(pending_hook_count, tuple):
        pending_hook_count = pending_hook_count[0]
    pending_hook_count = int(pending_hook_count or 0)

    hook_drift_findings = list(session.exec(
        select(FindingRecord)
        .where(
            FindingRecord.machine_id == machine_id,
            FindingRecord.rule_id.in_([  # type: ignore[attr-defined]
                "hook.rug_pull.content",
                "hook.rug_pull.command",
                "hook.unreadable",
                "hook.new",
            ]),
        )
        .order_by(FindingRecord.discovered_at.desc())  # type: ignore[attr-defined]
        .limit(30)
    ))
    hook_drift_cards: list[dict] = []
    for hf in hook_drift_findings:
        try:
            p = json.loads(hf.payload_json) if hf.payload_json else {}
        except (ValueError, TypeError):
            p = {}
        if not isinstance(p, dict):
            p = {}
        # Resolve the baseline row for accept/reject buttons. Slot identity is
        # (event_name, matcher, command_string); finding payload carries the
        # first two; command is the post-drift state for content drift and
        # comes from p["command"], whereas command-drift uses p["new_command"].
        cmd_key = p.get("new_command") or p.get("command") or ""
        bl = session.exec(
            select(HookBaseline).where(
                HookBaseline.machine_id == machine_id,
                HookBaseline.event_name == (p.get("event_name") or ""),
                HookBaseline.matcher == (p.get("matcher") or ""),
                HookBaseline.command_string == cmd_key,
            )
        ).first()
        hook_drift_cards.append({
            "title": p.get("title", hf.rule_id),
            "description": p.get("description", ""),
            "severity": hf.severity,
            "payload": p,
            "baseline_id": bl.id if bl is not None else None,
        })

    # Per-slot status for the badge on the existing «Хуки» block (Task 18).
    # Key shape: "event|matcher|command" — matches the Jinja string built in
    # the template (matcher/command default to "" when None).
    hook_baseline_rows = list(session.exec(
        select(HookBaseline).where(HookBaseline.machine_id == machine_id)
    ))
    hook_baseline_status_map: dict[str, str] = {}
    for hb in hook_baseline_rows:
        key = f"{hb.event_name}|{hb.matcher or ''}|{hb.command_string or ''}"
        hook_baseline_status_map[key] = hb.status

    # Skill + Agent TOFU baselines (specs/2026-06-02-skills-agents-baseline-design.md).
    from ccguard.server.db.models import AgentBaseline, SkillBaseline

    pending_skill_count = int(
        session.exec(
            select(_hbf.count(SkillBaseline.id)).where(
                SkillBaseline.machine_id == machine_id,
                SkillBaseline.status == "pending",
            )
        ).one() or 0
    )
    pending_agent_count = int(
        session.exec(
            select(_hbf.count(AgentBaseline.id)).where(
                AgentBaseline.machine_id == machine_id,
                AgentBaseline.status == "pending",
            )
        ).one() or 0
    )

    def _build_drift_cards(rule_ids: list[str], baseline_table) -> list[dict]:
        rows = list(session.exec(
            select(FindingRecord)
            .where(
                FindingRecord.machine_id == machine_id,
                FindingRecord.rule_id.in_(rule_ids),  # type: ignore[attr-defined]
            )
            .order_by(FindingRecord.discovered_at.desc())  # type: ignore[attr-defined]
            .limit(30)
        ))
        out: list[dict] = []
        for fr in rows:
            try:
                p = json.loads(fr.payload_json) if fr.payload_json else {}
            except (ValueError, TypeError):
                p = {}
            if not isinstance(p, dict):
                p = {}
            # Resolve baseline_id for accept/reject buttons. Slot identity is
            # (name, origin, parent_plugin).
            bl = session.exec(
                select(baseline_table).where(
                    baseline_table.machine_id == machine_id,
                    baseline_table.name == (p.get("name") or ""),
                    baseline_table.origin == (p.get("origin") or "local"),
                    baseline_table.parent_plugin == (p.get("parent_plugin") or None),
                )
            ).first()
            out.append({
                "title": p.get("title", fr.rule_id),
                "description": p.get("description", ""),
                "severity": fr.severity,
                "payload": p,
                "baseline_id": bl.id if bl is not None else None,
            })
        return out

    skill_drift_cards = _build_drift_cards(
        ["skill.new", "skill.rug_pull.content", "skill.drift.text"],
        SkillBaseline,
    )
    agent_drift_cards = _build_drift_cards(
        ["agent.new", "agent.rug_pull.dangerous", "agent.drift.text"],
        AgentBaseline,
    )

    # Память/инструкции (ASI06). Слот здесь — путь файла, а не (name, origin,
    # plugin), поэтому свой билдер, а не общий _build_drift_cards.
    from ccguard.server.db.models import MemoryBaseline

    pending_memory_count = int(
        session.exec(
            select(_hbf.count(MemoryBaseline.id)).where(
                MemoryBaseline.machine_id == machine_id,
                MemoryBaseline.status == "pending",
            )
        ).one() or 0
    )

    def _build_memory_cards() -> list[dict]:
        rows = list(session.exec(
            select(FindingRecord)
            .where(
                FindingRecord.machine_id == machine_id,
                FindingRecord.rule_id.in_(  # type: ignore[attr-defined]
                    ["memory.new", "memory.external", "memory.drift", "memory.removed"]
                ),
            )
            .order_by(FindingRecord.discovered_at.desc())  # type: ignore[attr-defined]
            .limit(30)
        ))
        out: list[dict] = []
        for fr in rows:
            try:
                p = json.loads(fr.payload_json) if fr.payload_json else {}
            except (ValueError, TypeError):
                p = {}
            if not isinstance(p, dict):
                p = {}
            bl = session.exec(
                select(MemoryBaseline).where(
                    MemoryBaseline.machine_id == machine_id,
                    MemoryBaseline.path == (p.get("path") or ""),
                )
            ).first()
            out.append({
                "title": p.get("title", fr.rule_id),
                "description": p.get("description", ""),
                "severity": fr.severity,
                "payload": p,
                "baseline_id": bl.id if bl is not None else None,
            })
        return out

    memory_drift_cards = _build_memory_cards()

    # Status map for badges in the existing skills/agents blocks. Key
    # composed in Jinja as "name|origin|parent_plugin".
    skill_status_map: dict[str, str] = {}
    for sb in session.exec(
        select(SkillBaseline).where(SkillBaseline.machine_id == machine_id)
    ):
        key = f"{sb.name}|{sb.origin}|{sb.parent_plugin or ''}"
        skill_status_map[key] = sb.status

    agent_status_map: dict[str, str] = {}
    for ab in session.exec(
        select(AgentBaseline).where(AgentBaseline.machine_id == machine_id)
    ):
        key = f"{ab.name}|{ab.origin}|{ab.parent_plugin or ''}"
        agent_status_map[key] = ab.status
    # Build a per-mcp_name status: 'red' if there's a critical rug pull,
    # 'amber' if warn, 'green' if baseline exists and no recent findings,
    # 'none' otherwise.
    status_by_name: dict[str, str] = {b.mcp_name: "green" for b in baseline_rows}
    for c in mcp_rug_cards:
        name = c["mcp_name"]
        if c["severity"] == "critical":
            status_by_name[name] = "red"
        elif c["severity"] == "warn" and status_by_name.get(name) != "red":
            status_by_name[name] = "amber"
    # Tier 3: surface the enforce-block stream (deny + fail_open) so anti-tamper
    # hard.* blocks are visible. rule_id is humanized in the template.
    enforce_blocks = [
        {
            "rule_id": b.rule_id,
            "reason": b.reason,
            "tool_name": b.tool_name,
            "received_at": b.received_at,
            "fail_open": b.fail_open,
        }
        for b in enforce_block_service.list_recent_blocks(session, machine_id, days=7)
    ]
    return templates.TemplateResponse(
        request,
        "machine_detail.html",
        {
            "user": user,
            "machine": machine,
            # Почему сенсор молчит (или не молчит). Отличает «сняли хуки» от
            # «ноутбук выключен» — без этого обе ситуации выглядят одинаково.
            "diagnosis": sensor_diagnosis.diagnose(session, machine),
            # Незакрытый вопрос по этой машине. Живёт дольше состояния: защиту
            # могли уже вернуть, а объяснения так и не дали.
            "incident": protection_incident_service.open_for_machine(
                session, machine_id
            ),
            "enforce_blocks": enforce_blocks,
            "inventory": get_latest_inventory_json(session, machine_id),
            "findings": build_explainable_findings(findings),
            "risk_series": risk_series,
            "risk_max": risk_max,
            "suppressions": suppressions,
            "top_actors": top_actors,
            "sync_freshness": sync_freshness,
            "mcp_rug_cards": mcp_rug_cards,
            "mcp_baseline_status": status_by_name,
            "pending_hook_count": pending_hook_count,
            "hook_drift_cards": hook_drift_cards,
            "hook_baseline_status_map": hook_baseline_status_map,
            "pending_skill_count": pending_skill_count,
            "skill_drift_cards": skill_drift_cards,
            "skill_baseline_status_map": skill_status_map,
            "pending_agent_count": pending_agent_count,
            "agent_drift_cards": agent_drift_cards,
            "agent_baseline_status_map": agent_status_map,
            "pending_memory_count": pending_memory_count,
            "memory_drift_cards": memory_drift_cards,
            "network_suspicious_cards": recent_network_cards_for_machine(
                session, machine_id
            ),
            "pi_read_cards": recent_pi_read_cards_for_machine(
                session, machine_id
            ),
            "csrf_token": _csrf_for(request),
        },
    )


@router.get("/admin/skills", response_class=HTMLResponse)
def skills_overview(
    request: Request,
    user: str = Depends(require_session),
    session: Session = Depends(get_session),
) -> HTMLResponse:
    """Fleet-wide LLM scan results for skill + agent artifacts."""
    from sqlalchemy import func as _func
    from ccguard.server.db.models import ScanResult

    rows = list(session.exec(
        select(ScanResult)
        .order_by(ScanResult.scanned_at.desc())  # type: ignore[attr-defined]
        .limit(100)
    ))
    enriched = [
        {
            "file_path": r.file_path,
            "scope": r.scope,
            "category": r.category,
            "risk_score": r.risk_score,
            "scanned_at": r.scanned_at,
            "suspicious": r.risk_score >= 40,
            # Detailed rationale (feat/skills-detailed-rationale). Backward-
            # compat: rows scanned before the field existed report None.
            "rationale": r.rationale,
            "explanation": getattr(r, "explanation", None),
            "quoted_snippet": getattr(r, "quoted_snippet", None),
            "model": r.model,
            "file_hash": r.file_hash,
            "ttl_expires_at": r.ttl_expires_at,
        }
        for r in rows
    ]
    total = int(session.exec(select(_func.count()).select_from(ScanResult)).one())
    suspicious = int(session.exec(
        select(_func.count()).select_from(ScanResult).where(ScanResult.risk_score >= 40)
    ).one())
    unique = int(session.exec(
        select(_func.count(_func.distinct(ScanResult.file_hash)))
    ).one())
    return templates.TemplateResponse(
        request,
        "skills_overview.html",
        {
            "user": user,
            "rows": enriched,
            "stats": {"total": total, "suspicious": suspicious, "unique": unique},
            "csrf_token": _csrf_for(request),
        },
    )


@router.get("/admin/skills-inventory", response_class=HTMLResponse)
def skills_inventory_page(
    request: Request,
    user: str = Depends(require_session),
    session: Session = Depends(get_session),
) -> HTMLResponse:
    """Fleet-wide aggregate of SkillBaseline + AgentBaseline.

    Surfaces divergent artifacts (same name has multiple dir_hash/
    file_hash across machines) as the primary signal. Single GROUP BY
    each, no joins (denormalized parent_plugin/source_marketplace).
    """
    from ccguard.server.services.skill_agent_fleet import (
        aggregate_agents,
        aggregate_skills,
    )
    skills = aggregate_skills(session)
    agents = aggregate_agents(session)

    def _source_url(marketplace: str | None) -> str | None:
        """Best-effort repo link from the marketplace id (no fabricated hosts)."""
        if not marketplace:
            return None
        if marketplace.startswith(("http://", "https://")):
            return marketplace
        # owner/repo slug → GitHub. Anything else stays a plain provenance label.
        if marketplace.count("/") == 1 and " " not in marketplace:
            return f"https://github.com/{marketplace}"
        return None

    def _group(summaries: list) -> list[dict]:
        groups: dict[tuple, dict] = {}
        for s in summaries:
            if s.parent_plugin:
                key = (s.parent_plugin, s.source_marketplace)
                label = f"{s.parent_plugin}@{s.source_marketplace or 'unknown'}"
                g = groups.get(key)
                if g is None:
                    g = groups[key] = {
                        "label": label, "plugin": s.parent_plugin,
                        "marketplace": s.source_marketplace,
                        "url": _source_url(s.source_marketplace),
                        "is_local": False, "items": [], "divergent": 0,
                    }
            else:
                key = ("__local__", None)
                g = groups.get(key)
                if g is None:
                    g = groups[key] = {
                        "label": "локальные (вне маркетплейса)", "plugin": None,
                        "marketplace": None, "url": None,
                        "is_local": True, "items": [], "divergent": 0,
                    }
            g["items"].append(s)
            if s.is_divergent:
                g["divergent"] += 1
        out = sorted(groups.values(), key=lambda g: (g["is_local"], -len(g["items"]), g["label"]))
        for g in out:
            g["count"] = len(g["items"])
        return out

    return templates.TemplateResponse(
        request,
        "skills_inventory.html",
        {
            "user": user,
            "skill_groups": _group(skills),
            "agent_groups": _group(agents),
            "skills_total": len(skills),
            "agents_total": len(agents),
            "skills_divergent_count": sum(1 for s in skills if s.is_divergent),
            "agents_divergent_count": sum(1 for a in agents if a.is_divergent),
            "csrf_token": _csrf_for(request),
        },
    )


@router.get("/_partials/skills-inventory/drill", response_class=HTMLResponse)
def skills_inventory_drill_partial(
    request: Request,
    kind: str,
    name: str,
    origin: str = "local",
    parent_plugin: str | None = None,
    _user: str = Depends(require_session),
    session: Session = Depends(get_session),
) -> HTMLResponse:
    """HTMX drill-down: list of (machine, hash, status) for one slot."""
    from ccguard.server.db.models import AgentBaseline, SkillBaseline
    from ccguard.server.services.skill_agent_fleet import machines_for_artifact

    table = SkillBaseline if kind == "skill" else AgentBaseline
    rows = machines_for_artifact(
        session, table, name=name, origin=origin,
        parent_plugin=parent_plugin or None,
    )
    return templates.TemplateResponse(
        request,
        "components/_skill_agent_drill.html",
        {"rows": rows, "kind": kind, "name": name},
    )


@router.get("/admin/report", response_class=HTMLResponse)
def compliance_report_page(
    request: Request,
    days: int = 30,
    user: str = Depends(require_session),
    session: Session = Depends(get_session),
) -> HTMLResponse:
    """Отчёт за период — документ для аудита, пригодный для печати в PDF."""
    from ccguard.server.services import compliance_report_service

    days = days if days in (7, 30, 90, 365) else 30
    report = compliance_report_service.build_report(session, days=days)
    return templates.TemplateResponse(
        request,
        "compliance_report.html",
        {"user": user, "r": report, "days": days},
    )


@router.get("/findings/export")
def findings_export(
    request: Request,
    format: str = "csv",
    severity: str | None = None,
    rule_id: str | None = None,
    machine_id: str | None = None,
    days: int | None = None,
    _user: str = Depends(require_session),
    session: Session = Depends(get_session),
) -> Response:
    """Скачать находки файлом: CSV для аудита, JSON для машинной обработки.

    Фильтры те же, что на странице находок, — оператор отбирает глазами и
    выгружает ровно то, что видит.
    """
    from ccguard.server.services import export_service

    fmt = "json" if format == "json" else "csv"
    rows = export_service.select_findings(
        session,
        severity=severity or None,
        rule_id=rule_id or None,
        machine_id=machine_id or None,
        since_days=days,
    )
    body = export_service.to_json(rows) if fmt == "json" else export_service.to_csv(rows)
    media = "application/json" if fmt == "json" else "text/csv"
    name = export_service.filename(fmt)
    return Response(
        content=body,
        media_type=f"{media}; charset=utf-8",
        headers={"Content-Disposition": f'attachment; filename="{name}"'},
    )


@router.get("/admin/canaries", response_class=HTMLResponse)
def canaries_page(
    request: Request,
    user: str = Depends(require_session),
    session: Session = Depends(get_session),
) -> HTMLResponse:
    """Приманки: подложенные фальшивые ключи и их состояние."""
    from ccguard.server.services import canary_service

    rows = canary_service.list_canaries(session)
    return templates.TemplateResponse(
        request,
        "canaries.html",
        {
            "user": user,
            "canaries": rows,
            "recipes": canary_service.RECIPES,
            "triggered_count": sum(1 for c in rows if c.status == "triggered"),
            # Значение только что созданной приманки показывается РОВНО ОДИН раз.
            # Ключ — идентификатор сессии (require_session возвращает именно его),
            # чтобы значение увидел только тот, кто её создал.
            "created": _CANARY_FLASH.pop(user, None),
            "csrf_token": _csrf_for(request),
        },
    )


# Одноразовая передача значения новой приманки на страницу после редиректа.
# В базе значения нет и не будет: если она утечёт вместе со значениями,
# атакующий получит список приманок и научится их обходить. Здесь оно живёт
# ровно до первого показа оператору.
_CANARY_FLASH: dict[str, dict] = {}


@router.post("/admin/canaries/create")
def canary_create(
    request: Request,
    token_type: str = Form(...),
    file_path: str = Form(""),
    machine_id: str = Form(""),
    label: str = Form(""),
    sid: str = Depends(require_session),
    _csrf: None = Depends(require_csrf),
    session: Session = Depends(get_session),
) -> RedirectResponse:
    """Создать приманку и показать её значение — единственный раз."""
    from ccguard.server.services import canary_service

    user_id = _resolve_user_id(session, sid)
    try:
        created = canary_service.create_canary(
            session,
            token_type=token_type,
            file_path=file_path.strip() or None,
            machine_id=machine_id.strip() or None,
            label=label.strip() or None,
            created_by=user_id,
        )
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e)) from e
    # Ключ — идентификатор сессии (тот же, что читает страница): значение увидит
    # ровно тот, кто создал приманку, и ровно один раз.
    _CANARY_FLASH[sid] = {
        "file_path": created.token.file_path,
        "file_content": created.file_content,
        "instructions": created.instructions,
        "token_type": created.token.token_type,
    }
    return RedirectResponse(url="/admin/canaries", status_code=303)


@router.post("/admin/canaries/{canary_id}/delete")
def canary_delete(
    canary_id: int,
    request: Request,
    _user: str = Depends(require_session),
    _csrf: None = Depends(require_csrf),
    session: Session = Depends(get_session),
) -> RedirectResponse:
    """Убрать приманку (перестаёт раздаваться агентам)."""
    from ccguard.server.services import canary_service

    canary_service.delete_canary(session, canary_id)
    return RedirectResponse(url="/admin/canaries", status_code=303)


@router.get("/admin/deploy", response_class=HTMLResponse)
def deploy_page(
    request: Request,
    platform: str = "linux",
    user: str = Depends(require_session),
    session: Session = Depends(get_session),
) -> HTMLResponse:
    """Готовый конфиг для массовой раскатки через домен / образ / Ansible."""
    from ccguard.server.services import deploy_config_service

    if platform not in deploy_config_service.SUPPORTED_PLATFORMS:
        platform = "linux"
    bundle = deploy_config_service.build_bundle(
        session, platform=platform, fallback_url=str(request.base_url),
    )
    return templates.TemplateResponse(
        request,
        "deploy.html",
        {
            "user": user,
            "b": bundle,
            "platform": platform,
            "platforms": deploy_config_service.SUPPORTED_PLATFORMS,
            # Машины, чей отпечаток хуков не совпал с раскатанным конфигом.
            # Проверка почти бесплатная: отпечаток уже приходит с сигналом.
            "drift": deploy_config_service.config_drift(session, platform=platform),
            "csrf_token": _csrf_for(request),
        },
    )


@router.post("/admin/deploy/server-url")
def deploy_set_server_url(
    request: Request,
    server_url: str = Form(...),
    platform: str = Form("linux"),
    _user: str = Depends(require_session),
    _csrf: None = Depends(require_csrf),
    session: Session = Depends(get_session),
) -> RedirectResponse:
    """Задать публичный адрес сервера, который попадёт в раскатанный конфиг."""
    from ccguard.server.services import deploy_config_service, settings_service

    settings_service.set_setting(
        session, deploy_config_service.SERVER_URL_KEY, server_url.strip(),
    )
    return RedirectResponse(url=f"/admin/deploy?platform={platform}", status_code=303)


@router.get("/admin/protection", response_class=HTMLResponse)
def protection_page(
    request: Request,
    user: str = Depends(require_session),
    session: Session = Depends(get_session),
) -> HTMLResponse:
    """Состояние защиты по флоту + разбор машин, где её нет.

    Совмещает два уровня намеренно: сверху — сколько машин под защитой прямо
    сейчас, ниже — эпизоды, по которым ждут ответа человека. Разносить это по
    двум страницам значит заставить оператора сверять их глазами.
    """
    from ccguard.server.services import protection_incident_service as pis
    from ccguard.server.services import sensor_diagnosis

    return templates.TemplateResponse(
        request,
        "protection.html",
        {
            "user": user,
            "fleet": sensor_diagnosis.fleet_summary(session),
            "diagnoses": sensor_diagnosis.diagnose_fleet(session),
            "incidents": pis.list_incidents(session, unresolved_only=False),
            "summary": pis.summary(session),
            "states": {
                "ok": sensor_diagnosis.OK, "idle": sensor_diagnosis.IDLE,
                "hooks_removed": sensor_diagnosis.HOOKS_REMOVED,
                "hooks_changed": sensor_diagnosis.HOOKS_CHANGED,
                "daemon_down": sensor_diagnosis.DAEMON_DOWN,
                "offline": sensor_diagnosis.OFFLINE,
                "unknown": sensor_diagnosis.UNKNOWN,
            },
            "csrf_token": _csrf_for(request),
        },
    )


@router.post("/admin/protection/{incident_id}/explain")
def protection_explain(
    incident_id: int,
    request: Request,
    explanation: str = Form(...),
    sid: str = Depends(require_session),
    _csrf: None = Depends(require_csrf),
    session: Session = Depends(get_session),
) -> RedirectResponse:
    """Записать причину, по которой на машине не было защиты."""
    from ccguard.server.services import protection_incident_service as pis

    try:
        pis.explain(
            session, incident_id,
            text=explanation, who=_resolve_user_id(session, sid),
        )
    except pis.NotFound as e:
        raise HTTPException(status_code=404) from e
    except (pis.AlreadyClosed, ValueError) as e:
        raise HTTPException(status_code=400, detail=str(e)) from e
    return RedirectResponse(url="/admin/protection", status_code=303)


@router.post("/admin/protection/{incident_id}/review")
def protection_review(
    incident_id: int,
    request: Request,
    verdict: str = Form(...),
    note: str = Form(""),
    sid: str = Depends(require_session),
    _csrf: None = Depends(require_csrf),
    session: Session = Depends(get_session),
) -> RedirectResponse:
    """Принять или отклонить объяснение — это и закрывает эпизод."""
    from ccguard.server.services import protection_incident_service as pis

    try:
        pis.review(
            session, incident_id,
            accept=(verdict == "accept"), who=_resolve_user_id(session, sid),
            note=note,
        )
    except pis.NotFound as e:
        raise HTTPException(status_code=404) from e
    except pis.AlreadyClosed as e:
        raise HTTPException(status_code=400, detail=str(e)) from e
    return RedirectResponse(url="/admin/protection", status_code=303)


@router.get("/admin/mcp-inventory", response_class=HTMLResponse)
def mcp_inventory_page(
    request: Request,
    user: str = Depends(require_session),
    session: Session = Depends(get_session),
) -> HTMLResponse:
    """Единая база MCP-серверов по всему флоту: список, хеши, расхождения
    между хостами (supply-chain / tamper-сигнал), статус ревью
    (проверено/не проверено)."""
    from ccguard.server.services.mcp_fleet_service import aggregate_mcp_servers

    rows = aggregate_mcp_servers(session)
    return templates.TemplateResponse(
        request,
        "mcp_inventory.html",
        {
            "user": user,
            "rows": rows,
            "total": len(rows),
            "divergent_count": sum(1 for r in rows if r.is_divergent),
            "unreviewed_count": sum(1 for r in rows if not r.fully_reviewed),
            # «Что люди сами себе понаставили» — серверы, объявленные в личном
            # конфиге разработчика и не пришедшие с плагином.
            "self_installed_count": sum(
                1 for r in rows if r.primary_scope == "user" and not r.from_plugin
            ),
            "plugin_count": sum(1 for r in rows if r.from_plugin),
            "csrf_token": _csrf_for(request),
        },
    )


@router.get("/_partials/mcp-inventory/drill", response_class=HTMLResponse)
def mcp_inventory_drill_partial(
    request: Request,
    name: str,
    _user: str = Depends(require_session),
    session: Session = Depends(get_session),
) -> HTMLResponse:
    """HTMX drill-down: по-машинные хеши + статус ревью для одного имени MCP."""
    from ccguard.server.services.mcp_fleet_service import machines_for_mcp

    rows = machines_for_mcp(session, name)
    return templates.TemplateResponse(
        request,
        "components/_mcp_fleet_drill.html",
        {"rows": rows, "name": name, "csrf_token": _csrf_for(request)},
    )


@router.post("/admin/mcp-inventory/review")
def mcp_inventory_review(
    request: Request,
    machine_id: str = Form(...),
    mcp_name: str = Form(...),
    sid: str = Depends(require_session),
    _csrf: None = Depends(require_csrf),
    session: Session = Depends(get_session),
) -> RedirectResponse:
    """Пометить один экземпляр MCP-сервера (на одной машине) проверенным."""
    from ccguard.server.services import mcp_baseline_service

    user_id = _resolve_user_id(session, sid)
    mcp_baseline_service.mark_reviewed(session, machine_id, mcp_name, reviewed_by=user_id)
    return RedirectResponse(url="/admin/mcp-inventory", status_code=303)


@router.post("/admin/mcp-inventory/review-all")
def mcp_inventory_review_all(
    request: Request,
    mcp_name: str = Form(...),
    sid: str = Depends(require_session),
    _csrf: None = Depends(require_csrf),
    session: Session = Depends(get_session),
) -> RedirectResponse:
    """Пометить ВСЕ непроверенные экземпляры этого MCP по всему флоту."""
    from ccguard.server.services import mcp_baseline_service

    user_id = _resolve_user_id(session, sid)
    mcp_baseline_service.mark_reviewed_fleet_wide(session, mcp_name, reviewed_by=user_id)
    return RedirectResponse(url="/admin/mcp-inventory", status_code=303)


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


@router.post("/admin/proposed-signals/draft-pi-from-text")
def proposed_pi_draft(
    request: Request,
    draft_json: str = Form(...),
    _user: str = Depends(require_session),
    _csrf: None = Depends(require_csrf),
    session: Session = Depends(get_session),
) -> RedirectResponse:
    """Manual paste of a prompt-injection pattern draft.

    Expects ``{category, pattern, description}`` JSON. Approve writes to
    SettingsRecord["pi.override.<category>"] — agent-side hot-reload of PI
    patterns is a follow-up; for now approved entries are admin-visible and
    ready for the next pattern catalog release.
    """
    from ccguard.server.services import proposed_signal_service as svc

    try:
        draft = json.loads(draft_json)
        if not isinstance(draft, dict):
            raise ValueError("draft_json must be a JSON object")
        svc.propose(
            session,
            draft=draft,
            source_kind="manual-pi",
            source_title="PI pattern (manual)",
            kind="pi_pattern",
        )
    except (ValueError, svc.InvalidDraft) as e:
        raise HTTPException(status_code=400, detail=f"invalid PI draft: {e}") from e
    return RedirectResponse(url="/admin/proposed-signals", status_code=303)


@router.post("/admin/proposed-signals/draft-from-llm")
def proposed_signals_draft_llm(
    request: Request,
    threat_text: str = Form(...),
    source_url: str = Form(""),
    source_title: str = Form(""),
    _user: str = Depends(require_session),
    _csrf: None = Depends(require_csrf),
    session: Session = Depends(get_session),
) -> RedirectResponse:
    """LLM-drafted variant (E2). Requires app.state.signal_drafter to be set
    (created at startup when ANTHROPIC_API_KEY is present)."""
    from ccguard.server.services import signal_drafter as drafter_mod

    drafter = getattr(request.app.state, "signal_drafter", None)
    if drafter is None:
        raise HTTPException(status_code=503, detail="llm drafter not configured")
    try:
        drafter_mod.draft_signal_from_text(
            session,
            drafter=drafter,
            threat_text=threat_text,
            source_kind="llm",
            source_url=source_url or None,
            source_title=source_title or None,
        )
    except drafter_mod.BudgetExhausted as e:
        raise HTTPException(status_code=429, detail=str(e)) from e
    except drafter_mod.DrafterError as e:
        raise HTTPException(status_code=400, detail=str(e)) from e
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


@router.post("/admin/proposed-signals/{row_id}/revert")
def proposed_signals_revert(
    row_id: int,
    request: Request,
    reason: str = Form(""),
    user: str = Depends(require_session),
    _csrf: None = Depends(require_csrf),
    session: Session = Depends(get_session),
) -> RedirectResponse:
    """Roll back a shipped signal (P3.3-7): delete its catalog.override.* so
    agents drop it next sync, mark the draft 'reverted'."""
    from ccguard.server.services import proposed_signal_service as svc

    try:
        svc.revert(session, row_id, reviewed_by=user, reason=reason or "(rolled back)")
    except svc.NotApproved as e:
        raise HTTPException(status_code=409, detail=str(e)) from e
    return RedirectResponse(url="/admin/proposed-signals", status_code=303)


@router.post("/admin/proposed-signals/trigger-discovery")
def proposed_signals_trigger_discovery(
    request: Request,
    _user: str = Depends(require_session),
    _csrf: None = Depends(require_csrf),
    session: Session = Depends(get_session),
) -> RedirectResponse:
    """Run the threat-intel discovery sweep ON DEMAND (P3.3-7), instead of
    waiting for the daily scheduler. Needs app.state.signal_drafter (the
    self-hosted Ollama default, or Anthropic fallback). Reuses the same monitor
    set as the scheduled sweep; each monitor is isolation-safe, so an offline
    source is logged, not fatal."""
    from ccguard.server.services import discovery_service
    from ccguard.server.services.source_monitors import default_monitors

    drafter = getattr(request.app.state, "signal_drafter", None)
    if drafter is None:
        raise HTTPException(status_code=503, detail="llm drafter not configured")
    monitors = getattr(request.app.state, "discovery_monitors", None) or default_monitors()
    discovery_service.tick(session, drafter=drafter, monitors=list(monitors))
    return RedirectResponse(url="/admin/proposed-signals", status_code=303)


@router.post("/admin/indicators/{row_id}/approve")
def indicator_approve(
    row_id: int,
    request: Request,
    user: str = Depends(require_session),
    _csrf: None = Depends(require_csrf),
    session: Session = Depends(get_session),
) -> RedirectResponse:
    """Promote a pending Path-2 indicator (e.g. an auto-collected IOC host) to
    active — it ships to agents on the next policy sync."""
    from ccguard.server.services import indicator_review_service as svc

    try:
        svc.approve(session, row_id, reviewed_by=user)
    except svc.NotPending as e:
        raise HTTPException(status_code=409, detail=str(e)) from e
    return RedirectResponse(url="/indicators", status_code=303)


@router.post("/admin/indicators/{row_id}/reject")
def indicator_reject(
    row_id: int,
    request: Request,
    user: str = Depends(require_session),
    _csrf: None = Depends(require_csrf),
    session: Session = Depends(get_session),
) -> RedirectResponse:
    """Reject a pending Path-2 indicator — kept for provenance, never served."""
    from ccguard.server.services import indicator_review_service as svc

    try:
        svc.reject(session, row_id, reviewed_by=user)
    except svc.NotPending as e:
        raise HTTPException(status_code=409, detail=str(e)) from e
    return RedirectResponse(url="/indicators", status_code=303)


@router.post("/admin/indicators/trigger-ioc-feeds")
def indicator_trigger_ioc_feeds(
    request: Request,
    _user: str = Depends(require_session),
    _csrf: None = Depends(require_csrf),
    session: Session = Depends(get_session),
) -> RedirectResponse:
    """Run the IOC host-feed sweep ON DEMAND, instead of waiting for the daily
    scheduler. Deterministic (no LLM). Reuses the same feed set as the scheduled
    sweep; each feed is isolation-safe, so an offline source is logged, not
    fatal. Fetched hosts land as pending indicators for review below."""
    from ccguard.server.services import ioc_feed_service

    feeds = getattr(request.app.state, "ioc_feeds", None) or ioc_feed_service.default_feeds()
    ioc_feed_service.run_ioc_feeds(session, feeds=list(feeds))
    return RedirectResponse(url="/indicators", status_code=303)


@router.post("/machines/{machine_id}/suppress")
def machine_suppress_signal(
    machine_id: str,
    request: Request,
    signal_id: str = Form(...),
    days: int = Form(30),
    reason: str = Form(""),
    user: str = Depends(require_session),
    _csrf: None = Depends(require_csrf),
    session: Session = Depends(get_session),
) -> RedirectResponse:
    """One-click suppression — closes the alert-fatigue loop."""
    from ccguard.server.services import suppression_service

    if days <= 0 or days > 365:
        raise HTTPException(status_code=400, detail="days must be 1..365")
    suppression_service.add(
        session, machine_id=machine_id, signal_id=signal_id,
        days=days, reason=reason or "(no reason)", by=user,
    )
    return RedirectResponse(url=f"/machines/{machine_id}", status_code=303)


@router.post("/machines/{machine_id}/unsuppress")
def machine_unsuppress_signal(
    machine_id: str,
    request: Request,
    signal_id: str = Form(...),
    _user: str = Depends(require_session),
    _csrf: None = Depends(require_csrf),
    session: Session = Depends(get_session),
) -> RedirectResponse:
    from ccguard.server.services import suppression_service

    suppression_service.remove(session, machine_id=machine_id, signal_id=signal_id)
    return RedirectResponse(url=f"/machines/{machine_id}", status_code=303)


@router.post("/machines/{machine_id}/mcp-baseline/accept")
def machine_accept_mcp_baseline(
    machine_id: str,
    request: Request,
    mcp_name: str = Form(...),
    sid: str = Depends(require_session),
    _csrf: None = Depends(require_csrf),
    session: Session = Depends(get_session),
) -> RedirectResponse:
    """Принять текущий снимок MCP-сервера как новый baseline.

    Используется когда админ подтвердил, что изменение description/definition
    легитимное (например, плагин действительно выпустил новый релиз и описание
    обновили). После accept последующий sync с тем же содержимым не будет
    вызывать новое finding. Также помечает MCP как проверенный (fleet review
    state), т.к. принятие изменения — это и есть ревью итогового состояния.
    """
    from ccguard.server.services import mcp_baseline_service
    user_id = _resolve_user_id(session, sid)
    mcp_baseline_service.accept_baseline(session, machine_id, mcp_name, reviewed_by=user_id)
    return RedirectResponse(url=f"/machines/{machine_id}", status_code=303)


def _resolve_user_id(session: Session, sid: str) -> str:
    """``require_session`` returns the opaque session id; baseline audit
    fields want the human-readable user_id. Resolve via WebSession."""
    from ccguard.server.db.models import WebSession
    row = session.get(WebSession, sid)
    return row.user_id if row is not None else "unknown"


@router.post("/machines/{machine_id}/hook-baseline/{baseline_id}/accept")
def machine_accept_hook_baseline(
    machine_id: str,
    baseline_id: int,
    request: Request,
    sid: str = Depends(require_session),
    _csrf: None = Depends(require_csrf),
    session: Session = Depends(get_session),
) -> RedirectResponse:
    """Принять pending/accepted_drift HookBaseline → active, записать кто."""
    from ccguard.server.services import hook_baseline_service
    user_id = _resolve_user_id(session, sid)
    try:
        hook_baseline_service.accept_baseline(
            session, machine_id=machine_id, baseline_id=baseline_id,
            accepting_user=user_id,
        )
    except LookupError as e:
        raise HTTPException(status_code=404, detail=str(e))
    session.commit()
    return RedirectResponse(url=f"/machines/{machine_id}", status_code=303)


@router.post("/machines/{machine_id}/hook-baseline/accept-all-pending")
def machine_accept_all_pending_hook_baselines(
    machine_id: str,
    request: Request,
    sid: str = Depends(require_session),
    _csrf: None = Depends(require_csrf),
    session: Session = Depends(get_session),
) -> RedirectResponse:
    """Bulk-промоут всех pending hook baselines для машины (bootstrap UX)."""
    from ccguard.server.services import hook_baseline_service
    user_id = _resolve_user_id(session, sid)
    hook_baseline_service.accept_all_pending(
        session, machine_id=machine_id, accepting_user=user_id,
    )
    session.commit()
    return RedirectResponse(url=f"/machines/{machine_id}", status_code=303)


@router.post("/machines/{machine_id}/hook-baseline/{baseline_id}/reject")
def machine_reject_hook_baseline(
    machine_id: str,
    baseline_id: int,
    request: Request,
    _user: str = Depends(require_session),
    _csrf: None = Depends(require_csrf),
    session: Session = Depends(get_session),
) -> RedirectResponse:
    """Отклонить baseline → status=removed. Сам хук из settings.json не удаляем."""
    from ccguard.server.services import hook_baseline_service
    try:
        hook_baseline_service.reject_and_mark(
            session, machine_id=machine_id, baseline_id=baseline_id,
        )
    except LookupError as e:
        raise HTTPException(status_code=404, detail=str(e))
    session.commit()
    return RedirectResponse(url=f"/machines/{machine_id}", status_code=303)


@router.post("/machines/{machine_id}/skill-baseline/{baseline_id}/accept")
def machine_accept_skill_baseline(
    machine_id: str,
    baseline_id: int,
    request: Request,
    sid: str = Depends(require_session),
    _csrf: None = Depends(require_csrf),
    session: Session = Depends(get_session),
) -> RedirectResponse:
    from ccguard.server.services import skill_baseline_service
    user_id = _resolve_user_id(session, sid)
    try:
        skill_baseline_service.accept_baseline(
            session, machine_id=machine_id, baseline_id=baseline_id,
            accepting_user=user_id,
        )
    except LookupError as e:
        raise HTTPException(status_code=404, detail=str(e))
    session.commit()
    return RedirectResponse(url=f"/machines/{machine_id}", status_code=303)


@router.post("/machines/{machine_id}/skill-baseline/accept-all-pending")
def machine_accept_all_pending_skill_baselines(
    machine_id: str,
    request: Request,
    sid: str = Depends(require_session),
    _csrf: None = Depends(require_csrf),
    session: Session = Depends(get_session),
) -> RedirectResponse:
    from ccguard.server.services import skill_baseline_service
    user_id = _resolve_user_id(session, sid)
    skill_baseline_service.accept_all_pending(
        session, machine_id=machine_id, accepting_user=user_id,
    )
    session.commit()
    return RedirectResponse(url=f"/machines/{machine_id}", status_code=303)


@router.post("/machines/{machine_id}/skill-baseline/{baseline_id}/reject")
def machine_reject_skill_baseline(
    machine_id: str,
    baseline_id: int,
    request: Request,
    _user: str = Depends(require_session),
    _csrf: None = Depends(require_csrf),
    session: Session = Depends(get_session),
) -> RedirectResponse:
    from ccguard.server.services import skill_baseline_service
    try:
        skill_baseline_service.reject_and_mark(
            session, machine_id=machine_id, baseline_id=baseline_id,
        )
    except LookupError as e:
        raise HTTPException(status_code=404, detail=str(e))
    session.commit()
    return RedirectResponse(url=f"/machines/{machine_id}", status_code=303)


@router.post("/machines/{machine_id}/agent-baseline/{baseline_id}/accept")
def machine_accept_agent_baseline(
    machine_id: str,
    baseline_id: int,
    request: Request,
    sid: str = Depends(require_session),
    _csrf: None = Depends(require_csrf),
    session: Session = Depends(get_session),
) -> RedirectResponse:
    from ccguard.server.services import agent_baseline_service
    user_id = _resolve_user_id(session, sid)
    try:
        agent_baseline_service.accept_baseline(
            session, machine_id=machine_id, baseline_id=baseline_id,
            accepting_user=user_id,
        )
    except LookupError as e:
        raise HTTPException(status_code=404, detail=str(e))
    session.commit()
    return RedirectResponse(url=f"/machines/{machine_id}", status_code=303)


@router.post("/machines/{machine_id}/agent-baseline/accept-all-pending")
def machine_accept_all_pending_agent_baselines(
    machine_id: str,
    request: Request,
    sid: str = Depends(require_session),
    _csrf: None = Depends(require_csrf),
    session: Session = Depends(get_session),
) -> RedirectResponse:
    from ccguard.server.services import agent_baseline_service
    user_id = _resolve_user_id(session, sid)
    agent_baseline_service.accept_all_pending(
        session, machine_id=machine_id, accepting_user=user_id,
    )
    session.commit()
    return RedirectResponse(url=f"/machines/{machine_id}", status_code=303)


@router.post("/machines/{machine_id}/agent-baseline/{baseline_id}/reject")
def machine_reject_agent_baseline(
    machine_id: str,
    baseline_id: int,
    request: Request,
    _user: str = Depends(require_session),
    _csrf: None = Depends(require_csrf),
    session: Session = Depends(get_session),
) -> RedirectResponse:
    from ccguard.server.services import agent_baseline_service
    try:
        agent_baseline_service.reject_and_mark(
            session, machine_id=machine_id, baseline_id=baseline_id,
        )
    except LookupError as e:
        raise HTTPException(status_code=404, detail=str(e))
    session.commit()
    return RedirectResponse(url=f"/machines/{machine_id}", status_code=303)


# --- Память/инструкции (ASI06): приём и отклонение baseline -----------------


@router.post("/machines/{machine_id}/memory-baseline/{baseline_id}/accept")
def machine_accept_memory_baseline(
    machine_id: str,
    baseline_id: int,
    request: Request,
    sid: str = Depends(require_session),
    _csrf: None = Depends(require_csrf),
    session: Session = Depends(get_session),
) -> RedirectResponse:
    from ccguard.server.services import memory_baseline_service
    user_id = _resolve_user_id(session, sid)
    try:
        memory_baseline_service.accept_baseline(
            session, machine_id=machine_id, baseline_id=baseline_id,
            accepting_user=user_id,
        )
    except LookupError as e:
        raise HTTPException(status_code=404, detail=str(e))
    session.commit()
    return RedirectResponse(url=f"/machines/{machine_id}", status_code=303)


@router.post("/machines/{machine_id}/memory-baseline/accept-all-pending")
def machine_accept_all_pending_memory_baselines(
    machine_id: str,
    request: Request,
    sid: str = Depends(require_session),
    _csrf: None = Depends(require_csrf),
    session: Session = Depends(get_session),
) -> RedirectResponse:
    from ccguard.server.services import memory_baseline_service
    user_id = _resolve_user_id(session, sid)
    memory_baseline_service.accept_all_pending(
        session, machine_id=machine_id, accepting_user=user_id,
    )
    session.commit()
    return RedirectResponse(url=f"/machines/{machine_id}", status_code=303)


@router.post("/machines/{machine_id}/memory-baseline/{baseline_id}/reject")
def machine_reject_memory_baseline(
    machine_id: str,
    baseline_id: int,
    request: Request,
    _user: str = Depends(require_session),
    _csrf: None = Depends(require_csrf),
    session: Session = Depends(get_session),
) -> RedirectResponse:
    from ccguard.server.services import memory_baseline_service
    try:
        memory_baseline_service.reject_and_mark(
            session, machine_id=machine_id, baseline_id=baseline_id,
        )
    except LookupError as e:
        raise HTTPException(status_code=404, detail=str(e))
    session.commit()
    return RedirectResponse(url=f"/machines/{machine_id}", status_code=303)


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
            self.id = r.id
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

    # Severity summary across ALL findings (unfiltered) — drives the filter pills.
    from sqlalchemy import func as _func
    sev_counts = dict(
        session.exec(select(FindingRecord.severity, _func.count()).group_by(FindingRecord.severity)).all()
    )
    sev_pills = [
        {"key": k, "label": lbl, "count": sev_counts.get(k, 0)}
        for k, lbl in (("critical", "критич."), ("block", "блок"), ("warn", "warn"), ("info", "info"))
    ]
    total_findings = sum(sev_counts.values())

    return templates.TemplateResponse(
        request,
        "findings_feed.html",
        {
            "user": user,
            "findings": findings,
            "sev_pills": sev_pills,
            "total_findings": total_findings,
            "shown": len(findings),
            "filters": {
                "severity": severity,
                "rule_id": rule_id,
                "machine_id": machine_id,
                "scope": scope or "all",
            },
            "csrf_token": _csrf_for(request),
        },
    )


# Payload keys already surfaced in the header / story sections — hidden from the
# raw key/value dump so it shows only the *extra* data.
_DETAIL_PAYLOAD_SKIP = {
    "rule_id", "severity", "title", "narrative", "rationale", "matched_value",
}


def _finding_detail_context(session: Session, finding) -> dict:
    """Assemble EVERYTHING about one finding for its dedicated page: the
    explainer/chain, the full payload, the producing detector + its techniques,
    the source artifact (injection snippet / MCP server / file), the machine,
    and the surrounding activity that makes up the story."""
    import json as _json

    from ccguard.server.db.models import (
        Detector,
        DetectorTechniqueMapping,
        FindingRecord,
        Machine,
        Technique,
    )
    from ccguard.server.web.finding_view import build_explainable_findings, humanize_rule

    rid = finding.rule_id
    enriched = build_explainable_findings([finding])[0]

    try:
        payload = _json.loads(finding.payload_json) if finding.payload_json else {}
        if not isinstance(payload, dict):
            payload = {}
    except (ValueError, TypeError):
        payload = {}

    def _fmt(v) -> str:
        if isinstance(v, (list, dict)):
            return _json.dumps(v, ensure_ascii=False)
        return str(v)

    payload_rows = [
        {"key": k, "value": _fmt(v)}
        for k, v in payload.items()
        if k not in _DETAIL_PAYLOAD_SKIP and v not in (None, "", [], {})
    ]

    # producing detector (correlation findings) + its technique bindings
    detector = None
    techniques: list[dict] = []
    det_row = None
    for d in session.exec(select(Detector)):
        rids = [r.strip() for r in (d.rule_ids or "").split(",") if r.strip()]
        if any(rid == r or rid.startswith(r) for r in rids):
            det_row = d
            break
    if det_row is not None:
        detector = {"key": det_row.detector_key, "name": det_row.name, "description": det_row.description}
        tech_ids = [
            m.technique_id
            for m in session.exec(
                select(DetectorTechniqueMapping).where(
                    DetectorTechniqueMapping.detector_key == det_row.detector_key
                )
            )
        ]
        for tid in sorted(set(tech_ids)):
            t = session.exec(select(Technique).where(Technique.technique_id == tid)).first()
            # ``covered`` gates the INTERNAL /coverage/{id} link: only techniques
            # present in the catalog have a coverage page (others 404), so we link
            # internally only when the row exists and fall back to MITRE otherwise.
            techniques.append(
                {"id": tid, "name": t.name if t else "", "url": t.url if t else None,
                 "covered": t is not None}
            )

    # catalog-signal finding (cred.read.*, c2.*, ...) — pull its ATT&CK technique
    if not techniques:
        from ccguard.server.web.finding_view import attack_url_for_signal, _SIGNAL_TO_TECHNIQUE
        tech = _SIGNAL_TO_TECHNIQUE.get(rid)
        if tech:
            t_row = session.exec(select(Technique).where(Technique.technique_id == tech)).first()
            techniques.append(
                {"id": tech, "name": t_row.name if t_row else "",
                 "url": attack_url_for_signal(rid) or (t_row.url if t_row else None),
                 "covered": t_row is not None}
            )

    # source artifact: split the "<identity>::<snippet>" matched_pattern that the
    # PI / dangerous detectors compose, so the page shows WHAT was injected / WHERE.
    artifact = None
    mv = payload.get("matched_value") or payload.get("matched_pattern") or ""
    if isinstance(mv, str) and mv:
        if "::" in mv:
            ident, snippet = mv.split("::", 1)
            artifact = {"source": ident, "snippet": snippet}
        else:
            artifact = {"source": "", "snippet": mv}

    machine = None
    is_fleet = finding.machine_id in ("_fleet", "_server")
    if not is_fleet:
        machine = session.get(Machine, finding.machine_id)

    # surrounding activity (the "what else happened" context / chain): other
    # findings on the same machine within +/- 48h, newest first.
    nearby: list[dict] = []
    if not is_fleet:
        lo = finding.discovered_at - timedelta(hours=48)
        hi = finding.discovered_at + timedelta(hours=48)
        rows = session.exec(
            select(FindingRecord)
            .where(FindingRecord.machine_id == finding.machine_id)
            .where(FindingRecord.discovered_at >= lo)
            .where(FindingRecord.discovered_at <= hi)
            .where(FindingRecord.id != finding.id)
            .order_by(FindingRecord.discovered_at.desc())  # type: ignore[attr-defined]
        ).all()
        for r in rows[:20]:
            nearby.append({
                "id": r.id, "rule_id": r.rule_id, "label": humanize_rule(r.rule_id),
                "severity": r.severity, "discovered_at": r.discovered_at,
                "before": r.discovered_at < finding.discovered_at,
            })

    return {
        "finding": finding,
        "rule_id": rid,
        "label": humanize_rule(rid),
        "severity": finding.severity,
        "machine_id": finding.machine_id,
        "machine": machine,
        "is_fleet": is_fleet,
        "discovered_at": finding.discovered_at,
        "explainer": enriched.get("explainer"),
        "details": enriched.get("details"),
        "payload": payload,
        "payload_rows": payload_rows,
        "detector": detector,
        "techniques": techniques,
        "artifact": artifact,
        "nearby": nearby,
        "title": payload.get("title"),
        "narrative": payload.get("narrative") or payload.get("rationale"),
    }


@router.get("/findings/{finding_id}", response_class=HTMLResponse)
def finding_detail_page(
    request: Request,
    finding_id: int,
    user: str = Depends(require_session),
    session: Session = Depends(get_session),
) -> HTMLResponse:
    from ccguard.server.db.models import FindingRecord

    finding = session.get(FindingRecord, finding_id)
    if finding is None:
        raise HTTPException(status_code=404, detail="finding not found")
    ctx = _finding_detail_context(session, finding)
    ctx["user"] = user
    ctx["csrf_token"] = _csrf_for(request)
    return templates.TemplateResponse(request, "finding_detail.html", ctx)


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
    actor_user: str = "",
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
            actor_user=actor_user or None,
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
                "actor_user": actor_user,
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


# Packaged starter policy (observe-mode, sensible defaults) — bundled inside the
# package so it is always present at runtime, unlike the repo-root examples/ dir.
_DEFAULT_POLICY_PATH = (
    Path(__file__).resolve().parent.parent / "data" / "default_policy.yaml"
)


def _render_no_policy_page(request: Request, *, user: str) -> HTMLResponse:
    """Graceful empty-state for a fresh instance with no published policy —
    instead of a raw 503 JSON. Offers a one-click 'load starter policy' CTA."""
    return templates.TemplateResponse(
        request,
        "policy_empty.html",
        {
            "user": user,
            "csrf_token": _csrf_for(request),
            "has_default": _DEFAULT_POLICY_PATH.exists(),
            "active_tab": "rules",
        },
        status_code=200,
    )


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
        return _render_no_policy_page(request, user=user)
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


@router.post("/policy/bootstrap-default", response_class=HTMLResponse)
def policy_bootstrap_default(
    request: Request,
    user: str = Depends(require_session),
    _csrf: None = Depends(require_csrf),
    session: Session = Depends(get_session),
) -> RedirectResponse:
    """Publish the bundled starter policy on a fresh instance (one-click from the
    empty-state). No-op (just redirect) if a policy already exists."""
    from ccguard.server.db.models import PolicyVersion
    from ccguard.server.services.policy_service import get_current_published

    if get_current_published(session) is None:
        if not _DEFAULT_POLICY_PATH.exists():
            raise HTTPException(status_code=500, detail="bundled default policy missing")
        text = _DEFAULT_POLICY_PATH.read_text()
        data = yaml.safe_load(text) or {}
        revision = int(data.get("meta", {}).get("revision", 1))
        session.add(
            PolicyVersion(
                revision=revision,
                status="published",
                yaml_text=text,
                created_by=f"bootstrap:{user}",
                published_at=datetime.now(UTC),
            )
        )
        session.commit()
    return RedirectResponse(url="/policy", status_code=303)


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
        return _render_no_policy_page(request, user=user)
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
    from ccguard.server.services.settings_service import (
        get_enforcement_mode,
        get_setting,
    )
    from ccguard.server.db.models import ScanResult

    from ccguard.server.services.settings_service import parse_budget

    cfg = _config(request)
    enabled = (get_setting(session, "llm_scanner_enabled") or "false").lower() == "true"
    budget = parse_budget(get_setting(session, "daily_call_budget"))
    enforcement_mode = get_enforcement_mode(session)
    scans = list(
        session.exec(
            select(ScanResult).order_by(ScanResult.scanned_at.desc()).limit(10)  # type: ignore[attr-defined]
        )
    )
    # P1 / Suspicious network calls: read-only view of active network
    # allowlist from the latest published policy. Источник истины — YAML под
    # ~/.ccguard/policy.yaml (см. settings.html section). Edit-UI оставлен в
    # YAML до v0.3 (см. TODO).
    network_allowlist: list[str] = []
    try:
        from ccguard.server.db.models import PolicyVersion
        import yaml as _yaml
        pv = session.exec(
            select(PolicyVersion)
            .where(PolicyVersion.status == "published")
            .order_by(PolicyVersion.revision.desc())  # type: ignore[attr-defined]
            .limit(1)
        ).first()
        if pv is not None:
            data = _yaml.safe_load(pv.yaml_text) or {}
            network_allowlist = list(
                (data.get("network") or {}).get("allowlist_hosts") or []
            )
    except Exception:
        # graceful — пустой список лучше, чем 500 на /settings.
        network_allowlist = []
    # initial-render values for the inline usage counter
    usage = _llm_usage_summary(session)
    from ccguard.server.services.alert_emitter import load_config as _load_alert_cfg
    _alert = _load_alert_cfg(session)
    return {
        "user": user,
        "tokens": list_tokens(session),
        "alert_settings": {
            "enabled": _alert.enabled,
            "webhook_url": _alert.webhook_url,
            "min_severity": _alert.min_severity,
            "format": _alert.fmt,
            "telegram_chat_id": _alert.telegram_chat_id,
        },
        "new_token": request.query_params.get("new_token"),
        "password_msg": request.query_params.get("password_msg"),
        "server_version": "0.1.0",
        "csrf_token": _csrf_for(request),
        "has_api_key": bool(cfg.anthropic_api_key),
        "llm_settings": {
            "llm_scanner_enabled": enabled,
            "daily_call_budget": budget,
        },
        "enforcement_mode": enforcement_mode,
        "scans": scans,
        "network_allowlist": network_allowlist,
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


@router.post("/admin/alert-settings")
def admin_alert_settings_save(
    request: Request,
    webhook_url: str = Form(""),
    min_severity: str = Form("block"),
    alert_format: str = Form("generic"),
    telegram_chat_id: str = Form(""),
    enabled: str = Form(""),
    reset_watermark: str = Form(""),
    user: str = Depends(require_session),
    _csrf: None = Depends(require_csrf),
    session: Session = Depends(get_session),
) -> Response:
    """Persist the alert-emitter config (webhook URL, min severity, format).

    On enable-or-URL-change (or an explicit "reset") the watermark is zeroed so
    the next tick fast-forwards to now (no historical-backlog flood). Validation:
    a non-empty URL must be http(s)://; enabling requires a URL.
    """
    from ccguard.server.services.settings_service import get_setting, set_setting

    url = webhook_url.strip()
    sev = min_severity if min_severity in ("info", "warn", "block", "critical") else "block"
    fmt = alert_format if alert_format in ("generic", "slack", "telegram") else "generic"
    is_enabled = bool(enabled)

    err: str | None = None
    if url and not (url.startswith("http://") or url.startswith("https://")):
        err = "Webhook URL должен начинаться с http:// или https://."
    elif is_enabled and not url:
        err = "Чтобы включить алерты, задайте webhook URL."
    elif is_enabled and fmt == "telegram" and not telegram_chat_id.strip():
        err = "Для формата Telegram укажите chat_id."
    if err is not None:
        ctx = _settings_context(request, session, user)
        ctx["alert_validation_error"] = err
        return templates.TemplateResponse(request, "settings.html", ctx, status_code=200)

    prev_url = (get_setting(session, "alert.webhook_url") or "").strip()
    prev_enabled = (get_setting(session, "alert.enabled") or "false").lower() in ("1", "true", "yes")

    set_setting(session, "alert.webhook_url", url)
    set_setting(session, "alert.min_severity", sev)
    set_setting(session, "alert.format", fmt)
    set_setting(session, "alert.telegram_chat_id", telegram_chat_id.strip())
    set_setting(session, "alert.enabled", "true" if is_enabled else "false")

    if reset_watermark or (is_enabled and (not prev_enabled or url != prev_url)):
        set_setting(session, "alert.last_finding_id", "0")

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

    # Non-HTMX callers (e.g. the /admin/skills detail-row form, where there
    # may not be a corresponding FindingRecord because the row was below the
    # finding-emit threshold) just want to land back on the listing page.
    # HTMX callers (findings_feed) keep the <tr> outerHTML swap.
    if request.headers.get("HX-Request", "").lower() != "true":
        return RedirectResponse(url="/admin/skills", status_code=303)

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


@router.post("/settings/enforcement-mode")
def settings_enforcement_mode(
    request: Request,
    mode: str = Form(...),
    _user: str = Depends(require_session),
    _csrf: None = Depends(require_csrf),
    session: Session = Depends(get_session),
) -> RedirectResponse:
    """Admin UI toggle for enforcement_mode (observe ↔ enforce).

    Writes SettingsRecord["enforcement_mode"]; the /api/v1/policy endpoint
    reads it and injects into the served policy, so agents pick up the
    change on their next sync (≤5min) — no code-change, no redeploy.
    """
    from ccguard.server.services.settings_service import set_setting

    if mode not in ("observe", "enforce"):
        raise HTTPException(status_code=400, detail="mode must be observe|enforce")
    set_setting(session, "enforcement_mode", mode)
    return RedirectResponse(url="/settings", status_code=303)


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
                "id": r.id,
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


@router.get("/_partials/dangerous/overview", response_class=HTMLResponse)
def dangerous_overview_partial(
    request: Request,
    _user: str = Depends(require_session),
    session: Session = Depends(get_session),
) -> HTMLResponse:
    """HTMX-polled card list of the most recent dangerous.* findings.

    Source: FindingRecord rows with rule_id LIKE 'dangerous.%'. Server-side
    enrichment (reason / remediation lookup) lives in
    :mod:`ccguard.server.services.dangerous_findings`.
    """
    from ccguard.server.services.dangerous_findings import recent_dangerous_cards
    items = recent_dangerous_cards(session, limit=10)
    return templates.TemplateResponse(
        request,
        "components/_dangerous_findings_overview.html",
        {"items": items},
    )


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
