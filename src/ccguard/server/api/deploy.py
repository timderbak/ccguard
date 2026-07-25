"""GET /api/v1/deploy/bundle — готовый конфиг для средства раскатки.

Отдаётся тому, кто собирает образ рабочей станции или раскатывает конфигурацию
доменной политикой: чтобы шаг «поставь ccguard» был машинным, а не абзацем в
инструкции, который на сотне машин выполнят по-разному.

Доступ — по тому же токену агента, что и остальные машинные вызовы. Секретов в
ответе нет по построению: токен в конфиге стоит подстановкой, а структура
хуков и адрес сервера и так известны каждому эндпоинту, где агент уже стоит.
"""
from __future__ import annotations

import logging

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from sqlmodel import Session

from ccguard.server.api.deps import get_session, require_token
from ccguard.server.services import deploy_config_service

log = logging.getLogger(__name__)

router = APIRouter(prefix="/api/v1")


@router.get("/deploy/bundle")
def deploy_bundle(
    request: Request,
    platform: str = Query("linux", description="linux | darwin | win32"),
    _token: str = Depends(require_token),
    session: Session = Depends(get_session),
) -> dict:
    """Конфиг для одной платформы: хуки, адрес сервера, скрипт установки."""
    try:
        return deploy_config_service.build_bundle(
            session, platform=platform, fallback_url=str(request.base_url),
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
