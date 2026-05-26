"""GET/POST /api/v1/findings.

GET: list findings with severity/rule filters — Phase 1 surface.

POST: agent-batch ingest from the Phase 5 findings_hook flusher (PI-01).
Accepts a JSON envelope ``{schema_version, machine_id, findings: [...]}``
and writes one :class:`FindingRecord` row per entry into the existing
v0.1 table (no new tables per RESEARCH §Project Constraints / D-1).

Auth: re-uses :func:`require_token` so the X-CCGuard-Token header gates the
write path identically to /api/v1/audit. T-05-04-04 mitigation.
"""

from __future__ import annotations

import json
from datetime import UTC, datetime
from typing import Literal

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field, ValidationError
from sqlmodel import Session, select

from ccguard.server.api.deps import get_session, require_token
from ccguard.server.db.models import FindingRecord, Machine

router = APIRouter(prefix="/api/v1")

_MAX_FINDINGS_PER_BATCH = 200
_FINDINGS_SCHEMA_VERSION = "1"


class _FindingWire(BaseModel):
    """One finding row as the agent flusher emits it.

    Mirrors the columns of ``findings_buffer`` minus delivery metadata. ``ts``
    arrives as an ISO-8601 string and is converted to datetime by pydantic.
    """

    ts: datetime
    rule_id: str = Field(min_length=1, max_length=128)
    # WR-05: agents only ever emit {info, warn, block}; the "critical"
    # severity is a server-side classification (see severity_critical
    # tagging) that must not be writable from agent-side input. Tighten
    # the wire schema so a malformed/hostile buffer row carrying
    # severity="critical" is rejected with a 422 instead of being
    # ingested as a real critical-severity finding.
    severity: Literal["info", "warn", "block"]
    title: str = Field(min_length=1, max_length=256)
    source: str = Field(min_length=1, max_length=64)
    matched_pattern: str = Field(max_length=220)  # 200 + truncation suffix
    tool_name: str = Field(min_length=1, max_length=128)


class _FindingsBatchIn(BaseModel):
    """Envelope POSTed by the findings_hook flusher."""

    schema_version: str
    machine_id: str = Field(min_length=1, max_length=128)
    findings: list[_FindingWire] = Field(min_length=1, max_length=_MAX_FINDINGS_PER_BATCH)


@router.get("/findings")
def list_findings(
    severity: str | None = Query(default=None, pattern="^(info|warn|block|critical)$"),
    rule_id: str | None = Query(default=None),
    limit: int = Query(default=100, ge=1, le=500),
    session: Session = Depends(get_session),
    _token: str = Depends(require_token),
) -> dict[str, object]:
    stmt = select(FindingRecord)
    if severity is not None:
        stmt = stmt.where(FindingRecord.severity == severity)
    if rule_id is not None:
        stmt = stmt.where(FindingRecord.rule_id == rule_id)
    stmt = stmt.order_by(FindingRecord.discovered_at.desc()).limit(limit)  # type: ignore[union-attr]
    rows = session.exec(stmt).all()

    label_cache: dict[str, str | None] = {}
    items: list[dict[str, object]] = []
    for r in rows:
        if r.machine_id not in label_cache:
            m = session.get(Machine, r.machine_id)
            label_cache[r.machine_id] = m.machine_label if m else None
        items.append(
            {
                "machine_id": r.machine_id,
                "machine_label": label_cache[r.machine_id],
                "discovered_at": r.discovered_at.isoformat(),
                "finding": json.loads(r.payload_json),
            }
        )
    return {"findings": items, "total": len(items)}


@router.post("/findings", status_code=201)
async def create_findings_batch(
    payload: _FindingsBatchIn,
    session: Session = Depends(get_session),
    _token: str = Depends(require_token),
) -> dict[str, object]:
    """Ingest a batch of findings from the agent flusher (PI-01).

    Stored shape: one :class:`FindingRecord` per inbound entry. ``payload_json``
    serializes the finding fields in the same JSON shape as Phase 1 emit sites,
    so existing GET /findings consumers and the web UI don't have to learn a
    new schema. ``discovered_at`` is set to the agent's ``ts`` (UTC).
    """
    try:
        # Re-validate even though FastAPI already did — defensive against the
        # decorator stack changing semantics under us.
        batch = _FindingsBatchIn.model_validate(payload.model_dump())
    except ValidationError as exc:  # pragma: no cover — re-validation
        raise HTTPException(status_code=422, detail=exc.errors()) from exc

    if batch.schema_version != _FINDINGS_SCHEMA_VERSION:
        # Major-version gate. v0.2 only knows "1"; anything else is a future
        # client we shouldn't silently coerce.
        raise HTTPException(
            status_code=422,
            detail=(
                f"unsupported findings schema_version {batch.schema_version!r} "
                f"(server expects {_FINDINGS_SCHEMA_VERSION!r})"
            ),
        )

    stored = 0
    for f in batch.findings:
        # The matched_pattern from the agent is already mask_secrets'd —
        # double-defense is not applied here because mask_secrets is
        # idempotent and the agent contract is authoritative for that field.
        payload_dict = {
            "rule_id": f.rule_id,
            "severity": f.severity,
            "title": f.title,
            "description": f.matched_pattern,
            "source": f.source,
            "recommendation": "",
            "matched_value": f.matched_pattern,
            "tool_name": f.tool_name,
        }
        # Normalize ts to UTC datetime.
        discovered_at = (
            f.ts.astimezone(UTC) if f.ts.tzinfo is not None else f.ts.replace(tzinfo=UTC)
        )
        session.add(
            FindingRecord(
                machine_id=batch.machine_id,
                inventory_id=None,
                rule_id=f.rule_id,
                severity=f.severity,
                discovered_at=discovered_at,
                payload_json=json.dumps(payload_dict, ensure_ascii=False),
            )
        )
        stored += 1
    session.commit()

    return {"accepted": stored, "stored": stored, "rejected": 0}
