"""LLM second-opinion on MCP description rug-pulls (out-of-band enrichment).

The inventory handler that detects ``mcp.rug_pull.description_changed`` is sync,
but the LLM scanner is async — so the finding is emitted WITHOUT a verdict (the
long-standing TODO in ``mcp_baseline_service``). This sweep, run in the scheduler
tick, attaches one after the fact: for recent description-change findings that
lack a verdict it scans the new description preview and writes
``llm_verdict`` / ``llm_rationale`` / ``llm_risk_score`` into the finding payload
(the machine-detail template already renders them when present).

Gated on ``llm_scanner_enabled`` + an available scanner; a scan failure is logged
and that finding is left for a later sweep. ``scanner`` is injected
(``Callable[[str], tuple[int, str]]``) so it tests offline without a live LLM.
"""
from __future__ import annotations

import json
import logging
from collections.abc import Callable
from datetime import UTC, datetime, timedelta

from sqlmodel import Session, select

from ccguard.server.db.models import FindingRecord
from ccguard.server.services.mcp_baseline_service import RULE_DESCRIPTION

log = logging.getLogger(__name__)

# (risk_score 0-100, rationale) — verdict >= threshold is "suspicious".
Scanner = Callable[[str], "tuple[int, str]"]
_SUSPICIOUS_THRESHOLD = 30


def review_descriptions(
    session: Session,
    *,
    scanner: Scanner,
    lookback_days: float = 7.0,
    limit: int = 20,
) -> dict[str, int]:
    """Attach an LLM verdict to recent description-change findings lacking one."""
    since = datetime.now(UTC) - timedelta(days=lookback_days)
    rows = session.exec(
        select(FindingRecord)
        .where(FindingRecord.rule_id == RULE_DESCRIPTION)  # type: ignore[arg-type]
        .where(FindingRecord.discovered_at >= since)  # type: ignore[operator]
        .order_by(FindingRecord.discovered_at.desc())  # type: ignore[attr-defined]
        .limit(limit)
    ).all()

    reviewed = errors = 0
    # Memoize by description text: an identical rug-pull description reported by
    # N fleet machines is one LLM call, not N (the sweep is budget-sensitive —
    # Anthropic API is the only paid dependency).
    memo: dict[str, tuple[int, str]] = {}
    for f in rows:
        try:
            payload = json.loads(f.payload_json) if f.payload_json else {}
        except (ValueError, TypeError):
            continue
        if not isinstance(payload, dict) or "llm_verdict" in payload:
            continue
        text = payload.get("new_preview")
        if not isinstance(text, str) or not text.strip():
            continue
        cached = memo.get(text)
        if cached is not None:
            score, rationale = cached
        else:
            try:
                score, rationale = scanner(text)
            except Exception as exc:  # noqa: BLE001 — one bad scan never aborts the sweep
                errors += 1
                log.warning("mcp llm review: scan failed for finding %s: %r", f.id, exc)
                continue
            memo[text] = (int(score), rationale or "")
        payload["llm_verdict"] = "suspicious" if int(score) >= _SUSPICIOUS_THRESHOLD else "benign"
        payload["llm_rationale"] = (rationale or "")[:500]
        payload["llm_risk_score"] = int(score)
        f.payload_json = json.dumps(payload, ensure_ascii=False, allow_nan=False)
        session.add(f)
        reviewed += 1

    if reviewed:
        session.commit()
    return {"reviewed": reviewed, "errors": errors, "candidates": len(rows)}


def make_llm_scanner(scan_service: object) -> Scanner:
    """Bridge the async LLM client behind a ScanService into a sync scanner
    (the sweep runs in the scheduler's worker thread, so ``asyncio.run`` is safe)."""
    import asyncio

    def _scan(text: str) -> tuple[int, str]:
        outcome = asyncio.run(
            scan_service._llm.scan_content(  # type: ignore[attr-defined]  # noqa: SLF001 — same-package bridge
                content=text, file_path="mcp://description", scope="mcp_description"
            )
        )
        return int(outcome.risk_score), (outcome.rationale or "")

    return _scan
