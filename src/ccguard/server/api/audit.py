"""POST /api/v1/audit — tool-use AND policy_apply event ingest.

Phase 1 (TUA-02) shipped this endpoint for tool-use events from the agent
flusher. Plan 04-04 extends it with an additive ``event_source`` discriminator:

* Body omitted ``event_source`` OR ``event_source == "tool_use"`` →
  existing v0.1 handler path, unchanged (regression-protected).
* ``event_source == "policy_apply"`` → new branch, persists
  :class:`PolicyApplyEvent` rows from the push-install pipeline (plan 04-03).
* Any other value → 400, so future event types can be added without silently
  colliding with old agents.

D-1 (schema_version=1): the policy_apply branch tolerates payloads with NO
``schema_version`` field (v0.1 agents). The legacy tool_use path still
requires ``schema_version`` and applies the major-version compatibility
gate (Phase 1 behavior).

Privacy contract (T-01-07): the request schema
(:class:`ccguard.schemas.tool_use.ToolUseEventIn`) deliberately has NO
``tool_input`` field — only a 16-hex fingerprint computed by the agent. If you
find yourself adding such a field, STOP — that is a privacy regression.

Security register:

* T-01-11 (spoofing): handled by ``require_token`` — see ``api.deps``.
* T-01-12 (machine_id tampering): documented v0.2 limitation — the token is not
  pinned to a specific ``machine_id``. v0.3 will associate token-id with each
  row for post-hoc detection.
* T-01-13 (DoS): ``MAX_BATCH=200`` enforced; 413 on overflow.
* T-01-15 (info-disclosure on bad token): ``require_token`` short-circuits with
  401 before any DB query runs.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import ValidationError
from sqlmodel import Session

from ccguard.schemas.audit import PolicyApplyBatchIn
from ccguard.schemas.tool_use import (
    SCHEMA_VERSION_AUDIT,
    AuditBatchIn,
    AuditBatchOut,
)
from ccguard.server.api.deps import get_session, require_token
from ccguard.server.db.models import PolicyApplyEvent, ToolUseEvent

router = APIRouter(prefix="/api/v1")

MAX_BATCH = 200

# Known event_source values. Anything else → 400 (future-proofing).
_KNOWN_EVENT_SOURCES = frozenset({"tool_use", "policy_apply"})


@router.post("/audit")
async def post_audit(
    request: Request,
    session: Session = Depends(get_session),
    _token: str = Depends(require_token),
) -> Any:
    """Ingest a batch of audit events.

    Discriminator: top-level ``event_source`` field on the JSON body.
    Missing or ``"tool_use"`` → legacy ToolUseEvent path. ``"policy_apply"``
    → new PolicyApplyEvent path (plan 04-04). Other values → 400.
    """
    try:
        raw: Any = await request.json()
    except Exception as exc:  # noqa: BLE001
        raise HTTPException(status_code=400, detail=f"invalid JSON body: {exc}") from exc

    if not isinstance(raw, dict):
        raise HTTPException(status_code=400, detail="body must be a JSON object")

    event_source = raw.get("event_source", "tool_use")
    if event_source not in _KNOWN_EVENT_SOURCES:
        raise HTTPException(
            status_code=400,
            detail=f"unknown event_source: {event_source!r}",
        )

    if event_source == "policy_apply":
        return _handle_policy_apply(raw, session)

    # Default: legacy tool_use path. Strip the optional event_source key so
    # AuditBatchIn (which forbids extras) still validates v0.1 bodies that
    # never included it.
    legacy_body = {k: v for k, v in raw.items() if k != "event_source"}
    try:
        payload = AuditBatchIn.model_validate(legacy_body)
    except ValidationError as exc:
        raise HTTPException(status_code=422, detail=exc.errors()) from exc
    return _handle_tool_use(payload, session)


def _handle_tool_use(payload: AuditBatchIn, session: Session) -> AuditBatchOut:
    """Phase 1 behavior — unchanged."""
    client_major = payload.schema_version.split(".", 1)[0]
    server_major = SCHEMA_VERSION_AUDIT.split(".", 1)[0]
    if client_major != server_major:
        raise HTTPException(
            status_code=422,
            detail=(
                f"schema_version {payload.schema_version} incompatible with "
                f"server {SCHEMA_VERSION_AUDIT}"
            ),
        )

    # Pydantic already enforces max_length=200 on AuditBatchIn.events, so we
    # would normally never reach this branch — but keep the defensive guard so
    # the contract is explicit at this layer (T-01-13).
    if len(payload.events) > MAX_BATCH:
        raise HTTPException(
            status_code=413,
            detail=f"batch too large (max {MAX_BATCH})",
        )

    now = datetime.now(UTC)
    for e in payload.events:
        session.add(
            ToolUseEvent(
                machine_id=payload.machine_id,
                ts=e.ts,
                received_at=now,
                tool_name=e.tool_name,
                fingerprint=e.fingerprint,
                decision=e.decision,
                result_status=e.result_status,
            )
        )
    session.commit()

    return AuditBatchOut(
        accepted=True,
        stored=len(payload.events),
        rejected=0,
        server_schema_version=SCHEMA_VERSION_AUDIT,
    )


def _handle_policy_apply(raw: dict[str, Any], session: Session) -> dict[str, Any]:
    """Plan 04-04 branch — persist one PolicyApplyEvent per inbound event."""
    body = {k: v for k, v in raw.items() if k != "event_source"}
    try:
        payload = PolicyApplyBatchIn.model_validate(body)
    except ValidationError as exc:
        raise HTTPException(status_code=422, detail=exc.errors()) from exc

    if len(payload.events) > MAX_BATCH:
        raise HTTPException(
            status_code=413,
            detail=f"batch too large (max {MAX_BATCH})",
        )

    for e in payload.events:
        session.add(
            PolicyApplyEvent(
                machine_id=e.machine_id,
                ts=e.ts,
                result=e.result,
                applied_count=e.applied_count,
                snapshot_id=e.snapshot_id,
                reason=e.reason,
                failed_file=e.failed_file,
                policy_revision=e.policy_revision,
            )
        )
    session.commit()

    return {
        "accepted": True,
        "stored": len(payload.events),
        "rejected": 0,
        "event_source": "policy_apply",
    }
