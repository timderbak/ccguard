"""GET /api/v1/policy — отдача политики с ETag-кэшированием.

E4: enriches the served policy with approved catalog overrides from
``SettingsRecord`` keys prefixed ``catalog.override.``. The ETag includes a
hash of the override set so changes invalidate downstream caches without a
policy revision bump.
"""

from __future__ import annotations

import hashlib
import json
from typing import Annotated

from fastapi import APIRouter, Depends, Header, Response, status
from sqlmodel import Session, select

from ccguard.server.api.deps import get_policy_loader, get_session, require_token
from ccguard.server.db.models import SettingsRecord
from ccguard.server.policy_loader import PolicyLoader

router = APIRouter(prefix="/api/v1")

_OVERRIDE_PREFIX = "catalog.override."


def _load_signal_overrides(session: Session) -> list[dict[str, object]]:
    """Read ``catalog.override.*`` rows from SettingsRecord, drop corrupt ones."""
    stmt = select(SettingsRecord).where(
        SettingsRecord.key.like(f"{_OVERRIDE_PREFIX}%")  # type: ignore[attr-defined]
    )
    out: list[dict[str, object]] = []
    for row in session.exec(stmt):
        try:
            payload = json.loads(row.value)
        except (ValueError, TypeError):
            continue
        if not isinstance(payload, dict):
            continue
        if not all(k in payload and isinstance(payload[k], str) for k in
                   ("id", "attack_technique", "pattern", "description")):
            continue
        out.append(payload)
    # Sort for deterministic ETag computation.
    out.sort(key=lambda x: str(x.get("id", "")))
    return out


def _overrides_etag_tag(overrides: list[dict[str, object]]) -> str:
    if not overrides:
        return ""
    blob = json.dumps(overrides, sort_keys=True, ensure_ascii=False).encode("utf-8")
    return hashlib.sha256(blob).hexdigest()[:12]


@router.get("/policy", response_model=None)
def get_policy(
    response: Response,
    if_none_match: Annotated[str | None, Header(alias="If-None-Match")] = None,
    loader: PolicyLoader = Depends(get_policy_loader),
    session: Session = Depends(get_session),
    _token: str = Depends(require_token),
) -> dict[str, object] | Response:
    policy, base_etag = loader.load_with_etag(session)
    overrides = _load_signal_overrides(session)

    tag = _overrides_etag_tag(overrides)
    # base_etag is like '"rev-7"'; weave the overrides tag inside the quotes
    # so it stays a valid HTTP ETag token.
    if tag:
        etag = base_etag[:-1] + f'+ov-{tag}"' if base_etag.endswith('"') else f'"{base_etag}+ov-{tag}"'
    else:
        etag = base_etag

    response.headers["ETag"] = etag
    response.headers["Cache-Control"] = "no-cache"

    if if_none_match and if_none_match == etag:
        return Response(status_code=status.HTTP_304_NOT_MODIFIED, headers={"ETag": etag})

    body = policy.model_dump(mode="json")
    if overrides:
        body["signal_overrides"] = overrides
    return body
