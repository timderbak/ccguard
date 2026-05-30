"""FastAPI-приложение ccguard-server. Точка входа `ccguard-server`."""

from __future__ import annotations

import logging
import os
from contextlib import asynccontextmanager
from collections.abc import AsyncIterator
from pathlib import Path

import uvicorn
from fastapi import FastAPI

from ccguard.server.api import audit, findings, health, inventory, machines, policy, scan
from ccguard.server.config import ServerConfig
from ccguard.server.db.session import init_db, make_engine
from ccguard.server.policy_loader import PolicyLoader
from ccguard.server.web.routes import router as web_router

logger = logging.getLogger("ccguard.server")


@asynccontextmanager
async def _lifespan(app: FastAPI) -> AsyncIterator[None]:
    # WR-01: Initialize scheduler attribute BEFORE any work that may raise so
    # the ``finally:`` cleanup block can safely reference ``app.state.scheduler``
    # without masking the original exception via AttributeError.
    app.state.scheduler = None
    cfg = ServerConfig.load(os.environ.get("CCGUARD_SERVER_CONFIG"))
    engine = make_engine(cfg.db_url)
    init_db(engine)
    from sqlmodel import Session as _Session
    from ccguard.server.services.settings_service import (
        seed_enforcement_mode,
        seed_llm_settings,
        seed_risk_settings,
        seed_sequence_settings,
    )
    from ccguard.server.services.token_service import bootstrap_env_tokens
    with _Session(engine) as _s:
        bootstrap_env_tokens(_s, env_tokens=[t.value for t in cfg.tokens])
        # Plan 03-01 D-04: seed LLM-scanner KV defaults on first startup;
        # subsequent restarts are no-ops, preserving admin edits.
        seed_llm_settings(_s)
        # Behavioral Detection Stage 2: seed risk-engine tunables.
        seed_risk_settings(_s)
        # Behavioral Detection Stage 3: seed sequence-detector tunables.
        seed_sequence_settings(_s)
        # Behavioral Detection Stage 5: seed enforcement_mode = observe.
        seed_enforcement_mode(_s)
    app.state.config = cfg
    app.state.engine = engine
    app.state.policy_loader = PolicyLoader(file_path=Path(cfg.policy_path), engine=engine)

    # Plan 03-04: wire ScanService if ANTHROPIC_API_KEY is set at startup.
    # When the key is missing, /scanner-config returns enabled=false and the
    # agent skips /scan-content entirely; if a stale agent does call it
    # anyway it gets 503 scanner_unavailable. Tests override the dependency
    # so this branch is non-load-bearing for unit/integration coverage.
    app.state.scan_service = None
    app.state.signal_drafter = None
    if cfg.llm_enabled_at_startup and cfg.anthropic_api_key:
        try:
            from ccguard.server.services.llm_client import LLMClient
            from ccguard.server.services.scan_service import ScanService
            app.state.scan_service = ScanService(
                engine=engine,
                llm_client=LLMClient(api_key=cfg.anthropic_api_key),
            )
        except Exception:  # noqa: BLE001 — scanner is optional at startup
            logger.exception("failed to initialize ScanService; scanner endpoints will 503")
            app.state.scan_service = None
        try:
            from ccguard.server.services.signal_drafter import AnthropicSignalDrafter
            app.state.signal_drafter = AnthropicSignalDrafter(api_key=cfg.anthropic_api_key)
        except Exception:  # noqa: BLE001 — drafter is optional at startup
            logger.exception("failed to initialize SignalDrafter; LLM draft endpoint will 503")
            app.state.signal_drafter = None

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
    from ccguard.server.services import discovery_service
    from ccguard.server.services.anomaly_service import tick as anomaly_tick
    from ccguard.server.services.risk_service import tick as risk_tick
    from ccguard.server.services.drift_service import tick as drift_tick
    from ccguard.server.services.sequence_service import tick as sequence_tick
    from ccguard.server.services.source_monitors.atlas import AtlasMonitor
    from ccguard.server.services.source_monitors.atomic_red_team import (
        AtomicRedTeamMonitor,
    )
    from ccguard.server.services.source_monitors.cve_ai_filter import (
        CVEAIFilterMonitor,
    )
    from ccguard.server.services.source_monitors.lakera_blog import (
        LakeraBlogMonitor,
    )
    from ccguard.server.services.source_monitors.mitre_attack import (
        MitreAttackMonitor,
    )
    from sqlmodel import Session as _SessionTick

    _DISCOVERY_MONITORS = (
        AtomicRedTeamMonitor(),
        MitreAttackMonitor(),
        AtlasMonitor(),
        LakeraBlogMonitor(),
        CVEAIFilterMonitor(),
    )

    if is_disabled():
        logger.info("anomaly scheduler disabled via CCGUARD_DISABLE_SCHEDULER")
    else:
        import asyncio

        def _tick_job_sync() -> None:
            try:
                with _SessionTick(engine) as s:
                    summary = anomaly_tick(s)
                    risk_summary = risk_tick(s)
                    sequence_summary = sequence_tick(s)
                    drift_summary = drift_tick(s)
                logger.info(
                    "anomaly tick: machines=%d findings=%d errors=%d",
                    summary["machines_evaluated"],
                    summary["findings_emitted"],
                    len(summary["errors"]),
                )
                logger.info(
                    "risk tick: machines=%d findings=%d errors=%d",
                    risk_summary["machines_evaluated"],
                    risk_summary["findings_emitted"],
                    len(risk_summary["errors"]),
                )
                logger.info(
                    "sequence tick: machines=%d findings=%d errors=%d",
                    sequence_summary["machines_evaluated"],
                    sequence_summary["findings_emitted"],
                    len(sequence_summary["errors"]),
                )
                logger.info(
                    "drift tick: machines=%d findings=%d errors=%d",
                    drift_summary["machines_evaluated"],
                    drift_summary["findings_emitted"],
                    len(drift_summary["errors"]),
                )
                # Rule Discovery sweep — once-per-day, gated by
                # discovery.last_run_at. Requires app.state.signal_drafter
                # (ANTHROPIC_API_KEY at startup); silently skip otherwise.
                drafter = getattr(app.state, "signal_drafter", None)
                if drafter is not None:
                    from datetime import UTC as _UTC, datetime as _dt
                    with _SessionTick(engine) as s2:
                        if discovery_service.should_run(s2, now=_dt.now(_UTC)):
                            disc_summary = discovery_service.tick(
                                s2, drafter=drafter, monitors=list(_DISCOVERY_MONITORS)
                            )
                            logger.info(
                                "discovery tick: seen=%d proposed=%d deduped=%d errors=%d",
                                disc_summary["items_seen"],
                                disc_summary["proposed"],
                                disc_summary["deduped"],
                                disc_summary["drafter_errors"],
                            )
            except Exception:  # noqa: BLE001 — scheduler job must not crash the loop
                logger.exception("scheduled tick raised")

        async def _tick_job() -> None:
            # WR-05: AsyncIOScheduler runs sync callables on the loop thread,
            # which would block all FastAPI request handlers for the duration
            # of the sweep (synchronous SQLite I/O on 100+ machines × 4 metrics
            # easily runs into seconds). Offload to the default thread pool so
            # the event loop stays responsive during ticks.
            await asyncio.to_thread(_tick_job_sync)

        scheduler = build_scheduler()
        try:
            start_scheduler(scheduler, _tick_job)
            app.state.scheduler = scheduler
        except Exception:
            # WR-01: If start_scheduler raises after partial setup, ensure
            # ``app.state.scheduler`` stays ``None`` so the lifespan teardown
            # does not attempt to shutdown a half-started scheduler.
            app.state.scheduler = None
            raise

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
    app.include_router(scan.router)
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
