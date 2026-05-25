"""POST /api/v1/audit — tool-use event ingest (TUA-02).

This is the server half of the agent→server audit pipeline. The agent
flusher batches tool-use events from its local SQLite WAL buffer and POSTs them
here; the server validates, applies the major-version schema gate, and persists
each event as a :class:`ToolUseEvent` row.

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

from fastapi import APIRouter, Depends, HTTPException
from sqlmodel import Session

from ccguard.schemas.tool_use import (
    SCHEMA_VERSION_AUDIT,
    AuditBatchIn,
    AuditBatchOut,
)
from ccguard.server.api.deps import get_session, require_token
from ccguard.server.db.models import ToolUseEvent

router = APIRouter(prefix="/api/v1")

MAX_BATCH = 200


@router.post("/audit", response_model=AuditBatchOut)
def post_audit(
    payload: AuditBatchIn,
    session: Session = Depends(get_session),
    _token: str = Depends(require_token),
) -> AuditBatchOut:
    """Ingest a batch of tool-use events.

    Major schema-version mismatch → 422 (agent must upgrade).
    Minor-version diff within the same major → accepted (server is graceful,
    per phase decision — old agents keep working as fields are added).
    """
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
