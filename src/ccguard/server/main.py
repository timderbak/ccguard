"""FastAPI-приложение ccguard-server. Точка входа `ccguard-server`."""

from __future__ import annotations

import logging
import os
from contextlib import asynccontextmanager
from collections.abc import AsyncIterator
from pathlib import Path

import uvicorn
from fastapi import FastAPI

from ccguard.server.api import findings, health, inventory, machines, policy
from ccguard.server.config import ServerConfig
from ccguard.server.db.session import init_db, make_engine
from ccguard.server.policy_loader import PolicyLoader

logger = logging.getLogger("ccguard.server")


@asynccontextmanager
async def _lifespan(app: FastAPI) -> AsyncIterator[None]:
    cfg = ServerConfig.load(os.environ.get("CCGUARD_SERVER_CONFIG"))
    engine = make_engine(cfg.db_url)
    init_db(engine)
    app.state.config = cfg
    app.state.engine = engine
    app.state.policy_loader = PolicyLoader(Path(cfg.policy_path))
    logger.info(
        "ccguard-server up: tokens=%d, db=%s, policy=%s",
        len(cfg.tokens),
        cfg.db_url,
        cfg.policy_path,
    )
    yield


def create_app() -> FastAPI:
    app = FastAPI(
        title="ccguard-server",
        version="0.1.0",
        description="Central server for ccguard agents.",
        lifespan=_lifespan,
    )
    app.include_router(health.router)
    app.include_router(inventory.router)
    app.include_router(policy.router)
    app.include_router(machines.router)
    app.include_router(findings.router)

    from ccguard.server.web.routes import router as web_router
    app.include_router(web_router)
    return app


app = create_app()


def serve() -> None:
    """Entry-point из pyproject scripts."""
    cfg = ServerConfig.load(os.environ.get("CCGUARD_SERVER_CONFIG"))
    uvicorn.run(
        "ccguard.server.main:app",
        host=cfg.host,
        port=cfg.port,
        log_level=cfg.log_level.lower(),
    )


if __name__ == "__main__":
    serve()
