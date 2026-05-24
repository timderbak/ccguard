"""GET /api/v1/policy — отдача политики с ETag-кэшированием."""

from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Depends, Header, Response, status
from sqlmodel import Session

from ccguard.server.api.deps import get_policy_loader, get_session, require_token
from ccguard.server.policy_loader import PolicyLoader

router = APIRouter(prefix="/api/v1")


@router.get("/policy", response_model=None)
def get_policy(
    response: Response,
    if_none_match: Annotated[str | None, Header(alias="If-None-Match")] = None,
    loader: PolicyLoader = Depends(get_policy_loader),
    session: Session = Depends(get_session),
    _token: str = Depends(require_token),
) -> dict[str, object] | Response:
    policy, etag = loader.load_with_etag(session)
    response.headers["ETag"] = etag
    response.headers["Cache-Control"] = "no-cache"

    if if_none_match and if_none_match == etag:
        return Response(status_code=status.HTTP_304_NOT_MODIFIED, headers={"ETag": etag})

    return policy.model_dump(mode="json")
