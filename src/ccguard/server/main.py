"""FastAPI-приложение ccguard-server. Точка входа `ccguard-server`."""

from __future__ import annotations

import logging
import os
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from pathlib import Path

import uvicorn
from fastapi import FastAPI
from fastapi.staticfiles import StaticFiles

from ccguard.server.api import audit, findings, health, heartbeat, inventory, machines, policy, scan
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

    from ccguard.server.services import indicator_seed_service
    from ccguard.server.services.settings_service import (
        seed_alert_settings,
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
        # P5 prod activation: CCGUARD_LLM_SCANNER_ENABLED, when explicitly set,
        # is authoritative each boot — flips the read_file semantic backstop on
        # (or off) at deploy time without a manual /settings toggle. Unset →
        # managed via the UI (the seeded default is off). Pair with
        # ANTHROPIC_API_KEY (which builds the ScanService below).
        if cfg.llm_scanner_enabled is not None:
            from ccguard.server.services.settings_service import set_setting
            set_setting(_s, "llm_scanner_enabled", "true" if cfg.llm_scanner_enabled else "false")
            logger.info(
                "llm_scanner_enabled=%s from CCGUARD_LLM_SCANNER_ENABLED (authoritative this boot)",
                cfg.llm_scanner_enabled,
            )
        # Behavioral Detection Stage 2: seed risk-engine tunables.
        seed_risk_settings(_s)
        # Behavioral Detection Stage 3: seed sequence-detector tunables.
        seed_sequence_settings(_s)
        # Behavioral Detection Stage 5: seed enforcement_mode = observe.
        seed_enforcement_mode(_s)
        # Alert emitter knobs (disabled by default; operator sets the webhook).
        seed_alert_settings(_s)
        # Reference-data seeds (indicators / taxonomy / crosswalk / detectors /
        # chain scenarios). Each loader is idempotent, but idempotence still
        # costs a probe per row (~180 ms of pure no-op work every restart), so
        # skip the whole block when the on-disk seed files are byte-identical to
        # what was already loaded. Edit any seed YAML (or ship an update) and the
        # digest changes → the block runs normally.
        from ccguard.server.services import seed_marker
        _digest = seed_marker.reference_digest()
        if seed_marker.is_current(_s, digest=_digest):
            logger.debug("reference seeds up to date (%s) — skipping", _digest)
        else:
            # ТЗ-05: load the vetted ThreatIndicator core (idempotent; a broken
            # seed file logs + loads nothing, never blocks startup).
            indicator_seed_service.load_seed(_s)
            # ТЗ-06: load ATLAS taxonomy, then migrate ТЗ-05 scalar technique
            # attribution into the many-to-many junction. Both idempotent.
            from ccguard.server.services import atlas_seed_service
            atlas_seed_service.load_atlas_seed(_s)
            atlas_seed_service.migrate_indicator_techniques(_s)
            # ТЗ-08: load the cross-framework crosswalk (≈ links) and register the
            # existing correlation detectors + their technique bindings. Both
            # idempotent; broken seeds log + load nothing, never block startup.
            from ccguard.server.services import taxonomy_seed_service
            taxonomy_seed_service.load_crosswalk_seed(_s)
            taxonomy_seed_service.load_detector_seed(_s)
            # ТЗ-09: load kill-chain scenarios as data (idempotent). The universal
            # chain_engine executes them in the scheduler tick beside the existing
            # correlators (sequence_service is untouched).
            from ccguard.server.services import chain_seed_service
            chain_seed_service.load_chain_seed(_s)
            seed_marker.mark_current(_s, digest=_digest)
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
    # P3.2: the signal drafter is INDEPENDENT of the scanner and defaults to the
    # self-hosted Ollama backend, so the enrichment loop runs on-prem WITHOUT an
    # API key. build_signal_drafter returns None only when no usable LLM backend
    # exists (Ollama unreachable/model-missing AND no Anthropic key) — the
    # discovery sweep then skips gracefully (the scheduler null-checks it).
    try:
        from ccguard.server.services.signal_drafter import build_signal_drafter
        app.state.signal_drafter = build_signal_drafter(cfg)
    except Exception:  # noqa: BLE001 — drafter is optional at startup
        logger.exception("failed to build signal drafter; discovery sweep will skip")
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
    from sqlmodel import Session as _SessionTick

    from ccguard.server.scheduler import (
        build_scheduler,
        is_disabled,
        register_sensor_sweep,
        shutdown_scheduler,
        start_scheduler,
    )
    from ccguard.server.services import discovery_service, ioc_feed_service
    from ccguard.server.services.alert_emitter import emit_new_alerts
    from ccguard.server.services.anomaly_service import tick as anomaly_tick
    from ccguard.server.services.chain_engine import tick as chain_tick
    from ccguard.server.services.drift_service import tick as drift_tick
    from ccguard.server.services.fleet_campaign_service import tick as fleet_campaign_tick
    from ccguard.server.services.identity_service import tick as identity_tick
    from ccguard.server.services.risk_service import tick as risk_tick
    from ccguard.server.services.sensor_health_service import tick as sensor_health_tick
    from ccguard.server.services.sequence_service import tick as sequence_tick
    from ccguard.server.services.slow_chain_service import tick as slow_chain_tick
    from ccguard.server.services.source_monitors import default_monitors
    from ccguard.server.services.supply_chain_escalation_service import (
        tick as ai_escalation_tick,
    )

    _DISCOVERY_MONITORS = tuple(default_monitors())
    # Same monitor set reachable by the manual "run discovery now" admin trigger
    # (routes.py), so the on-demand sweep and the scheduled sweep never drift.
    app.state.discovery_monitors = list(_DISCOVERY_MONITORS)

    _IOC_FEEDS = tuple(ioc_feed_service.default_feeds())
    # Same feed set reachable by the manual "run IOC feeds now" admin trigger.
    app.state.ioc_feeds = list(_IOC_FEEDS)

    if is_disabled():
        logger.info("anomaly scheduler disabled via CCGUARD_DISABLE_SCHEDULER")
    else:
        import asyncio

        def _maybe_review_mcp_descriptions(s: _SessionTick) -> dict | None:
            """LLM second-opinion sweep, gated on the scanner being enabled AND
            an initialized ScanService. Returns None when gated off so the tick
            logs nothing; never raises (its own try/except is in the caller)."""
            scan_svc = getattr(app.state, "scan_service", None)
            if scan_svc is None:
                return None
            from ccguard.server.services.settings_service import get_setting
            if (get_setting(s, "llm_scanner_enabled") or "false").lower() != "true":
                return None
            from ccguard.server.services import mcp_llm_review
            return mcp_llm_review.review_descriptions(
                s, scanner=mcp_llm_review.make_llm_scanner(scan_svc)
            )

        def _tick_job_sync() -> None:
            try:
                with _SessionTick(engine) as s:
                    summary = anomaly_tick(s)
                    risk_summary = risk_tick(s)
                    sequence_summary = sequence_tick(s)
                    chain_summary = chain_tick(s)
                    slow_chain_summary = slow_chain_tick(s)
                    drift_summary = drift_tick(s)
                    sensor_summary = sensor_health_tick(s)
                    # Опасные действия, выполненные агентом БЕЗ подтверждений
                    # человеком (permission_mode = bypassPermissions/dontAsk).
                    identity_summary = identity_tick(s)
                    # The moat correlator runs LAST so it sees every trigger /
                    # ioa.* finding the other engines just emitted this tick.
                    ai_escalation_summary = ai_escalation_tick(s)
                    # Fleet-scope campaign sweep (org-wide): same compromised
                    # component across N machines → ioa.fleet_campaign.
                    fleet_campaign_summary = fleet_campaign_tick(s)
                    # Push new findings (>= configured severity) to the operator
                    # webhook. Disabled by default; best-effort, never breaks the
                    # tick. Runs LAST so it sees every finding emitted above.
                    alert_summary = emit_new_alerts(s)
                    # Out-of-band LLM second-opinion on MCP description rug-pulls.
                    # The inventory handler is sync and the scanner async, so the
                    # rug-pull finding is emitted WITHOUT a verdict; this sweep
                    # attaches one after the fact. Gated on the scanner being
                    # enabled AND initialized; best-effort.
                    mcp_review_summary = _maybe_review_mcp_descriptions(s)
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
                    "chain tick: machines=%d scenarios=%d findings=%d errors=%d",
                    chain_summary["machines_evaluated"],
                    chain_summary["scenarios_active"],
                    chain_summary["findings_emitted"],
                    len(chain_summary["errors"]),
                )
                logger.info(
                    "slow_chain tick: machines=%d findings=%d errors=%d",
                    slow_chain_summary["machines_evaluated"],
                    slow_chain_summary["findings_emitted"],
                    len(slow_chain_summary["errors"]),
                )
                logger.info(
                    "drift tick: machines=%d findings=%d errors=%d",
                    drift_summary["machines_evaluated"],
                    drift_summary["findings_emitted"],
                    len(drift_summary["errors"]),
                )
                logger.info(
                    "sensor tick: machines=%d findings=%d errors=%d",
                    sensor_summary["machines_evaluated"],
                    sensor_summary["findings_emitted"],
                    len(sensor_summary["errors"]),
                )
                logger.info(
                    "identity tick: machines=%d findings=%d errors=%d",
                    identity_summary["machines_evaluated"],
                    identity_summary["findings_emitted"],
                    len(identity_summary["errors"]),
                )
                logger.info(
                    "ai_escalation tick: machines=%d findings=%d errors=%d",
                    ai_escalation_summary["machines_evaluated"],
                    ai_escalation_summary["findings_emitted"],
                    len(ai_escalation_summary["errors"]),
                )
                logger.info(
                    "fleet_campaign tick: campaigns=%d errors=%d",
                    fleet_campaign_summary["campaigns_emitted"],
                    len(fleet_campaign_summary["errors"]),
                )
                if alert_summary.get("enabled"):
                    logger.info(
                        "alert emit: emitted=%s failed=%s considered=%s",
                        alert_summary.get("emitted"),
                        alert_summary.get("failed"),
                        alert_summary.get("considered"),
                    )
                if mcp_review_summary and mcp_review_summary.get("reviewed"):
                    logger.info(
                        "mcp llm review: reviewed=%s errors=%s candidates=%s",
                        mcp_review_summary.get("reviewed"),
                        mcp_review_summary.get("errors"),
                        mcp_review_summary.get("candidates"),
                    )
                # Rule Discovery sweep — once-per-day, gated by
                # discovery.last_run_at. Needs app.state.signal_drafter (the
                # self-hosted Ollama default, or Anthropic fallback); if no
                # usable LLM backend was found at startup it is None → skip.
                drafter = getattr(app.state, "signal_drafter", None)
                if drafter is not None:
                    from datetime import UTC as _UTC
                    from datetime import datetime as _dt
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
                # IOC host-feed sweep — once-per-day, gated by
                # ioc_feed.last_run_at. Deterministic (no LLM), so it runs
                # regardless of the drafter: fetched hosts land as pending
                # indicators for admin review, never auto-live.
                from datetime import UTC as _IUTC
                from datetime import datetime as _idt
                with _SessionTick(engine) as s3:
                    if ioc_feed_service.should_run(s3, now=_idt.now(_IUTC)):
                        ioc_summary = ioc_feed_service.run_ioc_feeds(
                            s3, feeds=list(_IOC_FEEDS)
                        )
                        logger.info(
                            "ioc_feed tick: inserted=%d deduped=%d invalid=%d feed_errors=%d",
                            ioc_summary["inserted"],
                            ioc_summary["deduped"],
                            ioc_summary["invalid"],
                            len(ioc_summary["feed_errors"]),
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

        def _sensor_sweep_sync() -> None:
            # C1 (part 2): dedicated FAST sweep — only the sensor-silence
            # detector, so a suppressed/dead agent surfaces in ~1 min, not ~1h.
            # Cheap (one indexed scan) and idempotent (dedup via silent_since).
            try:
                with _SessionTick(engine) as s:
                    sensor_health_tick(s)
            except Exception:  # noqa: BLE001 — sweep must not crash the loop
                logger.exception("sensor sweep raised")

        async def _sensor_sweep_job() -> None:
            await asyncio.to_thread(_sensor_sweep_sync)

        scheduler = build_scheduler()
        try:
            start_scheduler(scheduler, _tick_job)
            register_sensor_sweep(scheduler, _sensor_sweep_job)
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
    app.include_router(heartbeat.router)
    app.include_router(scan.router)
    app.include_router(web_router)
    # Self-hosted UI assets (Tailwind build, htmx, fonts) — no runtime CDN, so
    # the console renders fully in an air-gapped / on-prem install.
    _static_dir = Path(__file__).parent / "web" / "static"
    app.mount("/static", StaticFiles(directory=str(_static_dir)), name="static")
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
