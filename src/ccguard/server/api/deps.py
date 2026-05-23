"""FastAPI dependencies: аутентификация, доступ к БД и policy."""

from __future__ import annotations

from collections.abc import Iterator
from typing import Annotated

from fastapi import Depends, Header, HTTPException, Request, status
from sqlmodel import Session

from ccguard.server.config import ServerConfig
from ccguard.server.db.session import session_factory
from ccguard.server.policy_loader import PolicyLoader


def get_config(request: Request) -> ServerConfig:
    cfg = getattr(request.app.state, "config", None)
    if cfg is None:
        raise RuntimeError("server config not initialized on app.state")
    return cfg


def get_policy_loader(request: Request) -> PolicyLoader:
    loader = getattr(request.app.state, "policy_loader", None)
    if loader is None:
        raise RuntimeError("policy loader not initialized on app.state")
    return loader


def get_session(request: Request) -> Iterator[Session]:
    engine = request.app.state.engine
    yield from session_factory(engine)


def require_token(
    x_ccguard_token: Annotated[str | None, Header(alias="X-CCGuard-Token")] = None,
    config: ServerConfig = Depends(get_config),
) -> str:
    if not x_ccguard_token or not config.is_token_valid(x_ccguard_token):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="invalid token")
    return x_ccguard_token
