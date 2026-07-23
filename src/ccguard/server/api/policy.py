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

from fastapi import APIRouter, Depends, Header, HTTPException, Response, status
from sqlmodel import Session, select

from ccguard.server.api.deps import get_policy_loader, get_session, require_token
from ccguard.server.db.models import SettingsRecord
from ccguard.server.policy_loader import PolicyLoader
from ccguard.server.services.indicator_override_service import (
    load_indicator_overrides,
    load_sensitive_path_overrides,
    load_suspicious_host_rules,
)
from ccguard.server.services.settings_service import get_enforcement_mode

router = APIRouter(prefix="/api/v1")

_OVERRIDE_PREFIX = "catalog.override."


def _combined_overrides(session: Session) -> list[dict[str, object]]:
    """Approved ProposedSignal overrides + active dangerous_command indicators.

    Both are served on the SAME agent wire (``signal_overrides``). Merged and
    deduped by id (ProposedSignal wins a collision, though the ``indicator.``
    namespace makes one impossible), sorted for a deterministic ETag.
    """
    merged: dict[str, dict[str, object]] = {}
    for ov in load_indicator_overrides(session):
        merged[str(ov["id"])] = ov
    for ov in load_sensitive_path_overrides(session):
        merged[str(ov["id"])] = ov
    for ov in _load_signal_overrides(session):  # ProposedSignal wins on collision
        merged[str(ov["id"])] = ov
    return sorted(merged.values(), key=lambda x: str(x.get("id", "")))


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
    try:
        policy, base_etag = loader.load_with_etag(session)
    except FileNotFoundError as exc:
        # Fresh, unconfigured instance (empty DB + no bootstrap file). Degrade
        # gracefully with a 503 instead of a 500 — the agent treats this as "no
        # policy yet" and keeps its cached policy; an admin loads a starter policy
        # via the /policy web empty-state (POST /policy/bootstrap-default).
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="no policy configured yet — publish one via the console",
        ) from exc
    overrides = _combined_overrides(session)
    # Active suspicious_host indicators merge into the policy's host rules below.
    store_host_rules = load_suspicious_host_rules(session)
    # Stage 5b: admin can flip enforcement_mode via /settings without editing
    # policy YAML. SettingsRecord override wins over the schema default.
    mode_override = get_enforcement_mode(session)

    tag_parts = []
    if overrides:
        tag_parts.append(f"ov-{_overrides_etag_tag(overrides)}")
    if store_host_rules:
        tag_parts.append(f"sh-{_overrides_etag_tag(store_host_rules)}")
    if mode_override != policy.enforcement_mode:
        tag_parts.append(f"em-{mode_override[:3]}")
    if tag_parts:
        suffix = "+" + "+".join(tag_parts)
        etag = base_etag[:-1] + f'{suffix}"' if base_etag.endswith('"') else f'"{base_etag}{suffix}"'
    else:
        etag = base_etag

    response.headers["ETag"] = etag
    response.headers["Cache-Control"] = "no-cache"

    if if_none_match and if_none_match == etag:
        return Response(status_code=status.HTTP_304_NOT_MODIFIED, headers={"ETag": etag})

    body = policy.model_dump(mode="json")
    body["enforcement_mode"] = mode_override
    if overrides:
        body["signal_overrides"] = overrides
    if store_host_rules:
        # Merge store-derived host rules into the policy's list, deduped by
        # pattern so a store indicator never shadows/duplicates a hardcoded rule
        # (the hardcoded block-tier rule wins). Done on the serialized body so the
        # loader's cached Policy object is never mutated.
        existing = body.get("suspicious_host_rules") or []
        seen_patterns = {r.get("pattern") for r in existing}
        merged = list(existing)
        for r in store_host_rules:
            if r["pattern"] not in seen_patterns:
                merged.append(r)
                seen_patterns.add(r["pattern"])  # also dedup store rules among themselves
        body["suspicious_host_rules"] = merged
    return body
