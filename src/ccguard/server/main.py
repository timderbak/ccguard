"""FastAPI-приложение ccguard-server. Точка входа `ccguard-server`."""

from __future__ import annotations

import logging
import os
from contextlib import asynccontextmanager
from collections.abc import AsyncIterator
from pathlib import Path

import uvicorn
from fastapi import FastAPI

from ccguard.server.api import audit, findings, health, inventory, machines, policy
from ccguard.server.config import ServerConfig
from ccguard.server.db.session import init_db, make_engine
from ccguard.server.policy_loader import PolicyLoader
from ccguard.server.web.routes import router as web_router

logger = logging.getLogger("ccguard.server")


@asynccontextmanager
async def _lifespan(app: FastAPI) -> AsyncIterator[None]:
    cfg = ServerConfig.load(os.environ.get("CCGUARD_SERVER_CONFIG"))
    engine = make_engine(cfg.db_url)
    init_db(engine)
    from sqlmodel import Session as _Session
    from ccguard.server.services.token_service import bootstrap_env_tokens
    with _Session(engine) as _s:
        bootstrap_env_tokens(_s, env_tokens=[t.value for t in cfg.tokens])
    app.state.config = cfg
    app.state.engine = engine
    app.state.policy_loader = PolicyLoader(file_path=Path(cfg.policy_path), engine=engine)

    # Trigger policy bootstrap from file if DB has no published policy yet.
    # Otherwise the web UI /policy route returns 503 until first agent sync.
    from sqlmodel import Session as _Session2
    with _Session2(engine) as _s_pol:
        try:
            app.state.policy_loader.load_with_etag(_s_pol)
        except FileNotFoundError:
            # No DB policy AND no bootstrap file — server can still start;
            # /policy will 503 until something seeds it. This is informational.
            logger.warning("no policy in DB and no bootstrap file; web /policy will 503 until seeded")

    logger.info(
        "ccguard-server up: tokens=%d, db=%s, policy=%s",
        len(cfg.tokens),
        cfg.db_url,
        cfg.policy_path,
    )

    # --- Phase 2 / Plan 02-03: anomaly scheduler ---------------------------
    from ccguard.server.scheduler import (
        build_scheduler,
        is_disabled,
        shutdown_scheduler,
        start_scheduler,
    )
    from ccguard.server.services.anomaly_service import tick as anomaly_tick
    from sqlmodel import Session as _SessionTick

    app.state.scheduler = None
    if is_disabled():
        logger.info("anomaly scheduler disabled via CCGUARD_DISABLE_SCHEDULER")
    else:
        def _tick_job() -> None:
            try:
                with _SessionTick(engine) as s:
                    summary = anomaly_tick(s)
                logger.info(
                    "anomaly tick: machines=%d findings=%d errors=%d",
                    summary["machines_evaluated"],
                    summary["findings_emitted"],
                    len(summary["errors"]),
                )
            except Exception:  # noqa: BLE001 — scheduler job must not crash the loop
                logger.exception("anomaly tick raised")

        scheduler = build_scheduler()
        start_scheduler(scheduler, _tick_job)
        app.state.scheduler = scheduler

    try:
        yield
    finally:
        if app.state.scheduler is not None:
            await shutdown_scheduler(app.state.scheduler)
            app.state.scheduler = None


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
    app.include_router(audit.router)
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
