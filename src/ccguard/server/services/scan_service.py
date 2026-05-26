"""LLM content scanner orchestrator (Plan 03-03).

Single entry point the HTTP layer (Plan 04) calls. Responsibilities:

1. **Cache lookup** by ``file_hash`` (sha256 of content) — hits within the
   30-day TTL skip the LLM call entirely and do not decrement the budget.
2. **Budget gate** — today's :class:`LLMCallLog` row count is compared against
   the ``daily_call_budget`` :class:`SettingsRecord`; exhaustion raises
   :class:`BudgetExhaustedError` (HTTP layer translates to 429).
3. **Scanner enable gate** — ``llm_scanner_enabled=false`` raises
   :class:`ScannerDisabledError` (HTTP layer translates to 409).
4. **Concurrency lock** — an instance-level :class:`asyncio.Lock` serializes
   Anthropic calls; one LLM request is in flight at a time, capping cost
   amplification from compromised agents (T-03-07).
5. **Persistence** — atomic-per-call: :class:`LLMCallLog` insert + UPSERT into
   :class:`ScanResult` keyed by ``file_hash`` + optional Finding emit, all in
   one Session.commit().
6. **Finding emit** — ``risk_score >= 30`` produces a
   :class:`FindingRecord` with ``rule_id = f"llm.scan.{category}"`` and severity
   per :func:`_severity_from_score` (D-04 locked).

Locked decisions (per 03-CONTEXT.md):

- D-01: severity ladder is ``info`` (<30), ``warn`` (30–70), ``critical`` (>70).
- D-02: server never stores content; :meth:`ScanService.rescan_file` therefore
  only invalidates the cache and returns :data:`RescanQueued` — the actual
  re-scan happens on the agent's next inventory cycle.
- D-04: emit threshold = ``risk_score >= 30``; rule_id format
  ``llm.scan.{category}``.

Privacy: no raw content is ever persisted — only ``file_hash`` and metadata
(category, rationale ≤500 chars, tokens, cost).

Concurrency / deployment constraints (CR-01):

The instance-level :class:`asyncio.Lock` serializes the *entire* critical
section (budget read + LLM call + LLMCallLog/ScanResult/Finding insert). This
makes the budget gate atomic-per-call within a single Python process. It is
**NOT** safe across multiple processes — :class:`asyncio.Lock` is per event
loop. **For v0.2, run uvicorn with ``--workers 1``.** Multi-process budget
enforcement would require a DB-level atomic counter (e.g. UPSERT with a
``CHECK (used < budget)`` constraint), which is deferred to v0.3.
"""

from __future__ import annotations

import asyncio
import hashlib
import json
from datetime import UTC, datetime, timedelta
from typing import Final, Literal, Protocol

from sqlalchemy.engine import Engine
from sqlalchemy import func
from sqlmodel import Session, select

from ccguard.server.db.models import (
    FindingRecord,
    LLMCallLog,
    ScanResult,
)
from ccguard.server.services.llm_client import ScanOutcome
from ccguard.server.services.settings_service import get_setting

# --- Constants -------------------------------------------------------------

CACHE_TTL: Final[timedelta] = timedelta(days=30)
EMIT_THRESHOLD: Final[int] = 30  # D-04
RULE_ID_PREFIX: Final[str] = "llm.scan."

Severity = Literal["info", "warn", "critical"]


# --- Exceptions / sentinels ------------------------------------------------


class BudgetExhaustedError(Exception):
    """Raised when today's LLM call budget has been spent.

    Carries no content — HTTP layer surfaces a generic 429 (T-03-09).
    """


class ScannerDisabledError(Exception):
    """Raised when ``llm_scanner_enabled=false``. HTTP layer → 409."""


class _RescanQueuedSentinel:
    """Type used as the singleton return value of :meth:`ScanService.rescan_file`."""

    __slots__ = ()

    def __repr__(self) -> str:  # pragma: no cover — debug aid only
        return "RescanQueued"


RescanQueued: Final = _RescanQueuedSentinel()


# --- LLM client protocol ---------------------------------------------------


class _LLMClientLike(Protocol):
    async def scan_content(
        self, content: str, file_path: str, scope: str
    ) -> ScanOutcome: ...


# --- Helpers ---------------------------------------------------------------


def _severity_from_score(score: int) -> Severity:
    """D-01 / D-04 severity ladder. Boundaries:

    * ``score < 30``  → ``"info"`` (NO finding is emitted at this band; see
      :meth:`ScanService.scan_file`. The function is still defined for the
      band so UI badges share a single source of truth.)
    * ``30 <= score <= 70`` → ``"warn"``
    * ``score > 70``  → ``"critical"``
    """
    if score < 30:
        return "info"
    if score <= 70:
        return "warn"
    return "critical"


def _file_hash(content: str) -> str:
    """sha256 hex of UTF-8-encoded content."""
    return hashlib.sha256(content.encode("utf-8")).hexdigest()


def _utc_day_start(now: datetime | None = None) -> datetime:
    """UTC midnight at the start of today (used as the budget window lower bound)."""
    n = now if now is not None else datetime.now(UTC)
    return n.replace(hour=0, minute=0, second=0, microsecond=0)


def _aware_utc(dt: datetime) -> datetime:
    """Coerce a naive datetime read back from SQLite to tz-aware UTC.

    SQLite stores datetimes as strings without timezone info, so SQLModel may
    return a naive ``datetime`` even though we wrote a tz-aware one. Comparing
    naive with aware raises ``TypeError`` — coerce defensively.
    """
    return dt if dt.tzinfo is not None else dt.replace(tzinfo=UTC)


# --- Service ---------------------------------------------------------------


class ScanService:
    """Orchestrate the LLM scanner. One instance per server process.

    The instance owns an :class:`asyncio.Lock` so concurrent ``scan_file``
    callers serialize at the LLM-call boundary. Cache hits and budget/setting
    reads run outside the lock to keep concurrency high for the happy path.
    """

    def __init__(self, engine: Engine, llm_client: _LLMClientLike) -> None:
        self._engine = engine
        self._llm = llm_client
        self._lock = asyncio.Lock()

    # ----- Public API -----

    async def scan_file(
        self,
        content: str,
        file_path: str,
        scope: Literal["agent", "skill"],
        *,
        force_rescan: bool = False,
    ) -> ScanResult:
        """Scan one file's content. Returns the persisted ``ScanResult`` row.

        Cache hit short-circuit happens BEFORE the budget gate so cache hits
        keep working after the daily budget is exhausted (read-only path).
        """
        file_hash = _file_hash(content)
        now = datetime.now(UTC)

        # --- 1. Cache lookup ---
        if not force_rescan:
            with Session(self._engine) as s:
                existing = s.exec(
                    select(ScanResult).where(ScanResult.file_hash == file_hash)
                ).one_or_none()
                if existing is not None and _aware_utc(existing.ttl_expires_at) > now:
                    return existing

        # --- 2. Enable gate (cheap, lock-free) ---
        with Session(self._engine) as s:
            enabled = (get_setting(s, "llm_scanner_enabled") or "false").lower() == "true"
        if not enabled:
            raise ScannerDisabledError("llm_scanner_enabled=false")

        # --- 3+4+5. Serialize budget read + LLM call + persist atomically.
        # CR-01: budget check + insert must happen in the same lock-protected
        # critical section AND in a single Session transaction. Two concurrent
        # callers can no longer both observe ``used == budget - 1`` and both
        # pass the gate. Single-process only — see module docstring.
        async with self._lock:
            with Session(self._engine) as s:
                budget_str = get_setting(s, "daily_call_budget") or "0"
                try:
                    budget = int(budget_str)
                except ValueError:
                    budget = 0
                day_start = _utc_day_start(now)
                used = s.exec(
                    select(func.count())  # type: ignore[arg-type]
                    .select_from(LLMCallLog)
                    .where(LLMCallLog.ts >= day_start)
                ).one()
                # SQLAlchemy returns either a scalar or a 1-tuple depending on
                # the path; normalize.
                used = used[0] if isinstance(used, tuple) else used
                if used >= budget:
                    raise BudgetExhaustedError(
                        f"daily LLM budget {budget} exhausted (used={used})"
                    )

                # LLM call still inside the lock so a single slow call cannot
                # let a second caller race past the gate (WR-03 sets a 30s
                # timeout on the SDK so the lock cannot be held indefinitely).
                outcome = await self._llm.scan_content(content, file_path, scope)

                s.add(
                    LLMCallLog(
                        ts=now,
                        file_hash=file_hash,
                        model=outcome.model,
                        input_tokens=outcome.input_tokens,
                        output_tokens=outcome.output_tokens,
                        cost_estimate_cents=outcome.cost_cents,
                    )
                )

                existing = s.exec(
                    select(ScanResult).where(ScanResult.file_hash == file_hash)
                ).one_or_none()
                ttl = now + CACHE_TTL
                if existing is None:
                    row = ScanResult(
                        file_hash=file_hash,
                        file_path=file_path,
                        scope=scope,
                        risk_score=outcome.risk_score,
                        category=outcome.category,
                        rationale=outcome.rationale,
                        scanned_at=now,
                        model=outcome.model,
                        ttl_expires_at=ttl,
                    )
                    s.add(row)
                else:
                    existing.file_path = file_path
                    existing.scope = scope
                    existing.risk_score = outcome.risk_score
                    existing.category = outcome.category
                    existing.rationale = outcome.rationale
                    existing.scanned_at = now
                    existing.model = outcome.model
                    existing.ttl_expires_at = ttl
                    s.add(existing)
                    row = existing

                if outcome.risk_score >= EMIT_THRESHOLD:
                    severity = _severity_from_score(outcome.risk_score)
                    payload = {
                        "file_hash": file_hash,
                        "risk_score": outcome.risk_score,
                        "category": outcome.category,
                        "rationale": outcome.rationale,
                        "scope": scope,
                        "file_path": file_path,
                        "model": outcome.model,
                    }
                    # Findings for the LLM scanner are server-wide
                    # artifact-level signals, not per-machine; we use a
                    # stable synthetic ``machine_id`` "_server" for this
                    # stream so the FindingRecord NOT-NULL column is
                    # satisfied without creating an arbitrary per-machine
                    # attribution.
                    s.add(
                        FindingRecord(
                            machine_id="_server",
                            inventory_id=None,
                            rule_id=f"{RULE_ID_PREFIX}{outcome.category}",
                            severity=severity,
                            discovered_at=now,
                            payload_json=json.dumps(payload, allow_nan=False),
                        )
                    )

                s.commit()
                s.refresh(row)
                return row

    async def rescan_file(self, file_hash: str) -> _RescanQueuedSentinel | None:
        """Invalidate the cache row for ``file_hash``; return :data:`RescanQueued`.

        Returns ``None`` if no row exists for that hash (nothing to invalidate).
        Server does not store content, so the actual re-scan happens when the
        agent next sends content matching this hash (cache miss path).
        """
        with Session(self._engine) as s:
            row = s.exec(
                select(ScanResult).where(ScanResult.file_hash == file_hash)
            ).one_or_none()
            if row is None:
                return None
            row.ttl_expires_at = datetime.now(UTC) - timedelta(seconds=1)
            s.add(row)
            s.commit()
        return RescanQueued

    async def get_daily_usage(self) -> dict:
        """Return today's LLM-scanner usage summary."""
        now = datetime.now(UTC)
        day_start = _utc_day_start(now)
        with Session(self._engine) as s:
            rows = list(s.exec(select(LLMCallLog).where(LLMCallLog.ts >= day_start)))
            enabled = (get_setting(s, "llm_scanner_enabled") or "false").lower() == "true"
            budget_str = get_setting(s, "daily_call_budget") or "0"
        try:
            budget = int(budget_str)
        except ValueError:
            budget = 0
        return {
            "used": len(rows),
            "budget": budget,
            "cost_cents": sum(r.cost_estimate_cents for r in rows),
            "enabled": enabled,
        }
