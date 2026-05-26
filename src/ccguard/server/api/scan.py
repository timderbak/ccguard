"""LLM content-scanner HTTP endpoints (Plan 03-04).

Two endpoints, both behind X-CCGuard-Token agent auth:

* ``GET  /api/v1/scanner-config`` — agent calls this first to decide whether
  to collect+send content at all. ``enabled`` is the AND of the runtime
  ``llm_scanner_enabled`` setting AND ``ANTHROPIC_API_KEY`` presence at startup
  (i.e. the server actually has a usable LLM client).
* ``POST /api/v1/scan-content`` — agent batch upload of base64-encoded,
  pre-masked file content. Server enforces size caps, calls
  :class:`ScanService` per item, and returns per-item results. Errors are
  surfaced per-item so one bad file never aborts the batch.

Privacy invariants (Plan 03-03):
- The server NEVER persists raw content; only the sha256 hash + classifier
  metadata land in ``ScanResult``.
- Server-side logs include ``file_path`` and ``file_hash`` but NEVER the
  decoded content bytes. The integration test
  ``test_scan_content_does_not_log_raw_content`` asserts this.

Size caps (per CONTEXT.md):
- 100 KiB soft cap → content is truncated and ``truncated=true`` is set on the
  response item. The scan still runs against the truncated prefix.
- 1 MiB hard cap → item is rejected with ``error="content_too_large"`` and no
  LLM call is made.
"""

from __future__ import annotations

import base64
import binascii
import logging
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Request, status
from sqlmodel import Session

from ccguard.schemas.scan import (
    ScanBatchResponse,
    ScanRequest,
    ScannerConfig,
    ScanResponseItem,
)
from ccguard.server.api.deps import get_config, get_session, require_token
from ccguard.server.config import ServerConfig
from ccguard.server.services.scan_service import (
    BudgetExhaustedError,
    ScannerDisabledError,
    ScanService,
    _severity_from_score,
)
from ccguard.server.services.settings_service import get_setting

logger = logging.getLogger("ccguard.server.scan")

router = APIRouter(prefix="/api/v1", tags=["scan"])

# Size caps (bytes of the *decoded* content). Match CONTEXT.md.
SOFT_CAP_BYTES = 100 * 1024  # 100 KiB → truncate
HARD_CAP_BYTES = 1024 * 1024  # 1 MiB → reject (matches ScannerConfig.max_file_bytes)


def get_scan_service(request: Request) -> ScanService:
    """Resolve the per-process :class:`ScanService` from ``app.state``.

    Tests override this via ``app.dependency_overrides`` to inject a service
    backed by a scripted LLM client. In production the service is built once
    in lifespan with the real :class:`LLMClient`.
    """
    svc = getattr(request.app.state, "scan_service", None)
    if svc is None:
        # Surface as 503 instead of 500 — the scanner subsystem is configured
        # to be absent (likely no ANTHROPIC_API_KEY). Old agents that don't
        # call /scanner-config first will see this and degrade gracefully.
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="scanner_unavailable",
        )
    return svc


@router.get("/scanner-config", response_model=ScannerConfig)
def get_scanner_config(
    session: Annotated[Session, Depends(get_session)],
    config: Annotated[ServerConfig, Depends(get_config)],
    _token: Annotated[str, Depends(require_token)],
) -> ScannerConfig:
    """Tell the agent whether to bother collecting+sending content this cycle.

    ``enabled = (Settings.llm_scanner_enabled == "true") AND (ANTHROPIC_API_KEY set)``.

    If either is false the agent should skip ``/scan-content``. Old agents
    (v0.1) don't know about this endpoint and won't call ``/scan-content``
    anyway — backward compatible.
    """
    setting = (get_setting(session, "llm_scanner_enabled") or "false").lower() == "true"
    enabled = setting and config.llm_enabled_at_startup
    return ScannerConfig(enabled=enabled, max_file_bytes=HARD_CAP_BYTES, schema_version=1)


@router.post("/scan-content", response_model=ScanBatchResponse)
async def post_scan_content(
    payload: ScanRequest,
    svc: Annotated[ScanService, Depends(get_scan_service)],
    _token: Annotated[str, Depends(require_token)],
) -> ScanBatchResponse:
    """Scan a batch of base64-encoded items.

    Per-item error handling (one bad file never kills the batch):
    - Invalid base64 → ``error="invalid_b64"``
    - >1 MiB decoded → ``error="content_too_large"`` (no LLM call)
    - >100 KiB decoded → truncated to 100 KiB, ``truncated=true``, scan runs
    - :class:`BudgetExhaustedError` → remaining items get ``error="budget_exhausted"``
      and we stop calling the LLM (cache hits would still work but at this
      point we have no way to know without trying — see note below)
    - :class:`ScannerDisabledError` for any item → ALL items get
      ``error="scanner_disabled"`` (scanner-disabled is a server-wide gate)
    - Unexpected exception per item → ``error="scanner_error"`` and we move on
    """
    response_items: list[ScanResponseItem] = []
    budget_exhausted_seen = False
    scanner_disabled_seen = False

    for item in payload.items:
        # Short-circuit if a prior item proved the scanner is disabled. The
        # disabled state is server-wide so no further items can succeed.
        if scanner_disabled_seen:
            response_items.append(
                ScanResponseItem(file_path=item.file_path, error="scanner_disabled")
            )
            continue

        # Once budget is exhausted, remaining items can't run new scans.
        # Cache hits could in principle still work, but ScanService raises
        # before checking the cache for force_rescan paths, and the simpler
        # contract here is "stop on budget exhausted". This matches the
        # plan's <behavior>: "later items get error=budget_exhausted".
        if budget_exhausted_seen:
            response_items.append(
                ScanResponseItem(file_path=item.file_path, error="budget_exhausted")
            )
            continue

        # 1. Decode base64.
        try:
            raw = base64.b64decode(item.content_b64, validate=True)
        except (binascii.Error, ValueError):
            logger.warning("scan-content: invalid base64 for %s", item.file_path)
            response_items.append(
                ScanResponseItem(file_path=item.file_path, error="invalid_b64")
            )
            continue

        # 2. Hard cap → reject without LLM call.
        if len(raw) > HARD_CAP_BYTES:
            logger.info(
                "scan-content: rejecting oversized item file_path=%s size=%d",
                item.file_path,
                len(raw),
            )
            response_items.append(
                ScanResponseItem(file_path=item.file_path, error="content_too_large")
            )
            continue

        # 3. Soft cap → truncate to 100 KiB, mark truncated=true.
        truncated = False
        if len(raw) > SOFT_CAP_BYTES:
            raw = raw[:SOFT_CAP_BYTES]
            truncated = True

        # 4. Decode utf-8 (lossy, matches agent-side encoding policy).
        content = raw.decode("utf-8", errors="replace")

        # 5. Probe cache BEFORE calling scan_file so we can populate
        # ``cached`` reliably in the response. WR-07: use the service's
        # public ``peek_cache`` so the route and the service share the same
        # hash + TTL logic and cannot drift if the cache key changes.
        try:
            cached = svc.peek_cache(content)
        except Exception:  # noqa: BLE001 — cache probe is best-effort metadata
            logger.debug("scan-content: cache probe failed; reporting cached=false")
            cached = False

        # 6. Call ScanService.scan_file.
        try:
            result = await svc.scan_file(content, item.file_path, item.scope)
        except BudgetExhaustedError:
            budget_exhausted_seen = True
            response_items.append(
                ScanResponseItem(file_path=item.file_path, error="budget_exhausted")
            )
            continue
        except ScannerDisabledError:
            scanner_disabled_seen = True
            response_items.append(
                ScanResponseItem(file_path=item.file_path, error="scanner_disabled")
            )
            continue
        except Exception:  # noqa: BLE001 — never crash the batch on one bad file
            # Log path/hash but NOT content — privacy invariant.
            logger.exception("scan-content: unexpected error for %s", item.file_path)
            response_items.append(
                ScanResponseItem(file_path=item.file_path, error="scanner_error")
            )
            continue

        response_items.append(
            ScanResponseItem(
                file_path=item.file_path,
                file_hash=result.file_hash,
                risk_score=result.risk_score,
                category=result.category,
                severity=_severity_from_score(result.risk_score),
                cached=cached,
                truncated=truncated,
            )
        )

        # Privacy-safe info log (path + hash + score, NOT content).
        logger.info(
            "scan-content: file_path=%s file_hash=%s risk_score=%d cached=%s truncated=%s",
            item.file_path,
            result.file_hash,
            result.risk_score,
            cached,
            truncated,
        )

    # If every item was scanner_disabled, return them all that way (covers the
    # edge case where the first item already triggered the disabled error).
    return ScanBatchResponse(schema_version=1, items=response_items)
