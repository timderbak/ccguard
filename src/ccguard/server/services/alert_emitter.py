"""Alert emitter — push new findings to an external webhook (SIEM / Slack / Telegram).

Findings are otherwise pull-only (UI + API), which was the sharpest "not a real
EDR yet" gap: the security team only learns about a critical finding if they
happen to open the console. After each engine tick this posts findings at or
above an operator-set severity to an operator-set webhook.

- **Exactly-once** across ticks via a watermark (last-alerted finding id). On
  first run it fast-forwards to the current max id, so enabling does NOT flood
  the channel with the whole backlog.
- **Best-effort**: a bad/unreachable webhook is logged and never breaks the tick.
- **Fully on-prem**: the webhook is whatever the operator points it at — an
  internal SIEM collector, a Slack/Mattermost incoming webhook, or a Telegram
  bot. No SaaS dependency.
"""
from __future__ import annotations

import json
import logging
from collections.abc import Callable
from dataclasses import dataclass

from sqlmodel import Session, select

from ccguard.server.db.models import FindingRecord
from ccguard.server.services import settings_service

log = logging.getLogger(__name__)

_ENABLED_KEY = "alert.enabled"
_URL_KEY = "alert.webhook_url"
_MIN_SEV_KEY = "alert.min_severity"
_FORMAT_KEY = "alert.format"
_CHAT_ID_KEY = "alert.telegram_chat_id"
_WATERMARK_KEY = "alert.last_finding_id"

_SEVERITY_RANK: dict[str, int] = {"info": 0, "warn": 1, "block": 2, "critical": 3}
_VALID_FORMATS = frozenset({"generic", "slack", "telegram"})
_MAX_BATCH = 200  # cap findings processed per tick so a backlog can't stall it
_HTTP_TIMEOUT_S = 10.0

HttpPost = Callable[[str, dict], bool]


@dataclass(frozen=True)
class AlertConfig:
    enabled: bool
    webhook_url: str
    min_severity: str
    fmt: str
    telegram_chat_id: str


def load_config(session: Session) -> AlertConfig:
    def _g(key: str, default: str) -> str:
        v = settings_service.get_setting(session, key)
        return v if v is not None else default

    fmt = _g(_FORMAT_KEY, "generic")
    if fmt not in _VALID_FORMATS:
        fmt = "generic"
    min_sev = _g(_MIN_SEV_KEY, "block")
    if min_sev not in _SEVERITY_RANK:
        min_sev = "block"
    return AlertConfig(
        enabled=_g(_ENABLED_KEY, "false").lower() in ("1", "true", "yes"),
        webhook_url=_g(_URL_KEY, "").strip(),
        min_severity=min_sev,
        fmt=fmt,
        telegram_chat_id=_g(_CHAT_ID_KEY, "").strip(),
    )


def _severity_ok(sev: str, min_sev: str) -> bool:
    return _SEVERITY_RANK.get(sev, 0) >= _SEVERITY_RANK.get(min_sev, 2)


def _summary_line(f: FindingRecord) -> str:
    return f"[{f.severity.upper()}] {f.rule_id} · {f.machine_id}"


def format_payload(f: FindingRecord, cfg: AlertConfig) -> dict:
    """Shape one finding for the configured channel."""
    line = _summary_line(f)
    if cfg.fmt == "slack":
        return {"text": f"ccguard · {line}"}
    if cfg.fmt == "telegram":
        return {"chat_id": cfg.telegram_chat_id, "text": f"ccguard · {line}"}
    # generic: a full structured event for a SIEM collector
    try:
        payload = json.loads(f.payload_json) if f.payload_json else {}
    except (ValueError, TypeError):
        payload = {}
    return {
        "source": "ccguard",
        "summary": line,
        "finding": {
            "id": f.id,
            "machine_id": f.machine_id,
            "rule_id": f.rule_id,
            "severity": f.severity,
            "discovered_at": f.discovered_at.isoformat() if f.discovered_at else None,
            "payload": payload,
        },
    }


def _default_http_post(url: str, body: dict) -> bool:
    import httpx

    try:
        with httpx.Client(timeout=_HTTP_TIMEOUT_S) as client:
            resp = client.post(url, json=body)
        return 200 <= resp.status_code < 300
    except Exception as exc:  # noqa: BLE001 — emitter is best-effort
        log.warning("alert: webhook POST failed: %r", exc)
        return False


def emit_new_alerts(session: Session, *, http_post: HttpPost | None = None) -> dict[str, object]:
    """Post findings newer than the watermark and at/above min_severity.

    Returns a summary dict. Never raises — a webhook failure advances the
    watermark anyway (at-most-once per finding; we do not retry a flaky sink
    forever) and is reported in the summary.
    """
    cfg = load_config(session)
    if not cfg.enabled or not cfg.webhook_url:
        return {"enabled": False, "emitted": 0, "failed": 0, "considered": 0}
    if cfg.fmt == "telegram" and not cfg.telegram_chat_id:
        log.warning("alert: telegram format but no telegram_chat_id set — skipping")
        return {"enabled": True, "emitted": 0, "failed": 0, "considered": 0,
                "skipped": "no_telegram_chat_id"}

    post = http_post or _default_http_post

    raw = settings_service.get_setting(session, _WATERMARK_KEY)

    # First-ever run (key ABSENT, not merely "0"): fast-forward to the current
    # max id so enabling does not replay the whole historical backlog. A stored
    # "0" is a real watermark (empty-at-enable DB) and must NOT re-fast-forward.
    if raw is None:
        max_id = session.exec(
            select(FindingRecord.id).order_by(FindingRecord.id.desc()).limit(1)  # type: ignore[attr-defined]
        ).first()
        settings_service.set_setting(session, _WATERMARK_KEY, str(int(max_id or 0)))
        return {"enabled": True, "emitted": 0, "failed": 0, "considered": 0,
                "initialized_watermark": int(max_id or 0)}

    try:
        watermark = int(raw)
    except (TypeError, ValueError):
        watermark = 0

    rows = session.exec(
        select(FindingRecord)
        .where(FindingRecord.id > watermark)  # type: ignore[operator]
        .order_by(FindingRecord.id.asc())  # type: ignore[attr-defined]
        .limit(_MAX_BATCH)
    ).all()

    emitted = failed = considered = 0
    highest = watermark
    for f in rows:
        highest = max(highest, f.id or highest)
        if not _severity_ok(f.severity, cfg.min_severity):
            continue
        considered += 1
        if post(cfg.webhook_url, format_payload(f, cfg)):
            emitted += 1
        else:
            failed += 1

    if highest > watermark:
        settings_service.set_setting(session, _WATERMARK_KEY, str(highest))

    return {"enabled": True, "emitted": emitted, "failed": failed,
            "considered": considered, "watermark": highest}
