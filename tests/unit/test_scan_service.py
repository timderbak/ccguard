"""Unit tests for scan_service (Plan 03-03).

Covers:
- cache hit returns without LLM call
- budget gate: exhaustion raises BudgetExhaustedError
- scanner disabled raises ScannerDisabledError
- finding emission threshold + severity mapping
- UPSERT idempotent by file_hash
- rescan_file expires cache and returns RescanQueued
- asyncio.Lock serializes concurrent calls
"""

from __future__ import annotations

import asyncio
import hashlib
import json
from datetime import UTC, datetime, timedelta

import pytest
from sqlmodel import Session, select

from ccguard.server.db.models import (
    FindingRecord,
    LLMCallLog,
    ScanResult,
    SettingsRecord,
)
from ccguard.server.db.session import init_db, make_engine
from ccguard.server.services import scan_service
from ccguard.server.services.llm_client import ScanOutcome
from ccguard.server.services.scan_service import (
    BudgetExhaustedError,
    RescanQueued,
    ScannerDisabledError,
    ScanService,
)
from ccguard.server.services.settings_service import seed_llm_settings


def _engine_with_settings(enabled: bool = True, budget: int = 100):
    eng = make_engine("sqlite://")
    init_db(eng)
    with Session(eng) as s:
        seed_llm_settings(s)
        s.exec(  # type: ignore[call-overload]
            select(SettingsRecord).where(SettingsRecord.key == "llm_scanner_enabled")
        ).first().value = "true" if enabled else "false"
        s.exec(  # type: ignore[call-overload]
            select(SettingsRecord).where(SettingsRecord.key == "daily_call_budget")
        ).first().value = str(budget)
        s.commit()
    return eng


class _MockLLMClient:
    """Records calls and returns a scripted ScanOutcome.

    Supports per-call entry/exit timestamps for the concurrency assertion.
    """

    def __init__(
        self,
        *,
        risk_score: int = 50,
        category: str = "benign",
        hold_seconds: float = 0.0,
    ) -> None:
        self.calls: list[dict] = []
        self.entry_exit: list[tuple[float, float]] = []
        self.risk_score = risk_score
        self.category = category
        self._hold = hold_seconds

    async def scan_content(self, content: str, file_path: str, scope: str):
        entry = asyncio.get_event_loop().time()
        self.calls.append({"content": content, "file_path": file_path, "scope": scope})
        if self._hold:
            await asyncio.sleep(self._hold)
        exit_ = asyncio.get_event_loop().time()
        self.entry_exit.append((entry, exit_))
        return ScanOutcome(
            risk_score=self.risk_score,
            category=self.category,
            rationale="test rationale",
            input_tokens=100,
            output_tokens=20,
            cost_cents=1,
            model="claude-haiku-4-5-20251001",
        )


@pytest.mark.asyncio
async def test_severity_mapping_pure_function() -> None:
    assert scan_service._severity_from_score(0) == "info"
    assert scan_service._severity_from_score(29) == "info"
    assert scan_service._severity_from_score(30) == "warn"
    assert scan_service._severity_from_score(70) == "warn"
    assert scan_service._severity_from_score(71) == "critical"
    assert scan_service._severity_from_score(100) == "critical"


@pytest.mark.asyncio
async def test_cache_hit_skips_llm_and_budget() -> None:
    eng = _engine_with_settings(enabled=True, budget=1)
    llm = _MockLLMClient(risk_score=10, category="benign")
    svc = ScanService(engine=eng, llm_client=llm)

    r1 = await svc.scan_file("content-A", "agents/foo.md", "agent")
    assert r1.risk_score == 10
    assert len(llm.calls) == 1

    # Second call with same content — should be a cache hit; no extra LLM call.
    r2 = await svc.scan_file("content-A", "agents/foo.md", "agent")
    assert len(llm.calls) == 1
    assert r2.file_hash == r1.file_hash

    # And no budget decrement: there should be exactly one LLMCallLog row.
    with Session(eng) as s:
        rows = list(s.exec(select(LLMCallLog)))
        assert len(rows) == 1


@pytest.mark.asyncio
async def test_budget_exhausted_raises() -> None:
    eng = _engine_with_settings(enabled=True, budget=2)
    llm = _MockLLMClient(risk_score=10)
    svc = ScanService(engine=eng, llm_client=llm)

    await svc.scan_file("A", "a.md", "agent")
    await svc.scan_file("B", "b.md", "agent")

    with pytest.raises(BudgetExhaustedError):
        await svc.scan_file("C", "c.md", "agent")

    # Only 2 calls were made.
    assert len(llm.calls) == 2


@pytest.mark.asyncio
async def test_scanner_disabled_raises() -> None:
    eng = _engine_with_settings(enabled=False, budget=100)
    llm = _MockLLMClient()
    svc = ScanService(engine=eng, llm_client=llm)
    with pytest.raises(ScannerDisabledError):
        await svc.scan_file("anything", "x.md", "agent")
    assert llm.calls == []


@pytest.mark.asyncio
async def test_no_finding_below_threshold() -> None:
    eng = _engine_with_settings()
    llm = _MockLLMClient(risk_score=29, category="benign")
    svc = ScanService(engine=eng, llm_client=llm)
    await svc.scan_file("low", "a.md", "agent")

    with Session(eng) as s:
        findings = list(s.exec(select(FindingRecord)))
        assert findings == []


@pytest.mark.asyncio
async def test_finding_warn_at_threshold() -> None:
    eng = _engine_with_settings()
    llm = _MockLLMClient(risk_score=30, category="jailbreak")
    svc = ScanService(engine=eng, llm_client=llm)
    await svc.scan_file("mid", "agents/x.md", "agent")

    with Session(eng) as s:
        findings = list(s.exec(select(FindingRecord)))
        assert len(findings) == 1
        f = findings[0]
        assert f.rule_id == "llm.scan.jailbreak"
        assert f.severity == "warn"
        payload = json.loads(f.payload_json)
        assert payload["risk_score"] == 30
        assert payload["category"] == "jailbreak"
        assert payload["scope"] == "agent"
        assert payload["file_path"] == "agents/x.md"
        assert payload["file_hash"]


@pytest.mark.asyncio
async def test_finding_critical_above_70() -> None:
    eng = _engine_with_settings()
    llm = _MockLLMClient(risk_score=71, category="data-exfil")
    svc = ScanService(engine=eng, llm_client=llm)
    await svc.scan_file("bad", "skills/p.md", "skill")

    with Session(eng) as s:
        f = list(s.exec(select(FindingRecord)))[0]
        assert f.severity == "critical"
        assert f.rule_id == "llm.scan.data-exfil"


@pytest.mark.asyncio
async def test_upsert_idempotent_by_file_hash() -> None:
    eng = _engine_with_settings()
    llm = _MockLLMClient(risk_score=10)
    svc = ScanService(engine=eng, llm_client=llm)
    await svc.scan_file("same", "a.md", "agent")
    # Force rescan path to trigger fresh LLM call but same file_hash
    await svc.rescan_file(hashlib.sha256(b"same").hexdigest())
    await svc.scan_file("same", "a.md", "agent")

    with Session(eng) as s:
        rows = list(s.exec(select(ScanResult)))
        assert len(rows) == 1


@pytest.mark.asyncio
async def test_rescan_expires_and_returns_sentinel() -> None:
    eng = _engine_with_settings()
    llm = _MockLLMClient(risk_score=10)
    svc = ScanService(engine=eng, llm_client=llm)
    res = await svc.scan_file("Z", "z.md", "agent")
    file_hash = res.file_hash

    sentinel = await svc.rescan_file(file_hash)
    assert sentinel is RescanQueued or isinstance(sentinel, type(RescanQueued))

    with Session(eng) as s:
        row = s.exec(select(ScanResult).where(ScanResult.file_hash == file_hash)).one()
        # ttl_expires_at can be naive or tz-aware UTC depending on SQLite storage
        ttl = row.ttl_expires_at
        if ttl.tzinfo is None:
            ttl = ttl.replace(tzinfo=UTC)
        assert ttl < datetime.now(UTC)

    # Next scan should trigger a fresh call.
    pre = len(llm.calls)
    await svc.scan_file("Z", "z.md", "agent")
    assert len(llm.calls) == pre + 1


@pytest.mark.asyncio
async def test_lock_serializes_concurrent_calls() -> None:
    eng = _engine_with_settings(budget=100)
    llm = _MockLLMClient(risk_score=10, hold_seconds=0.05)
    svc = ScanService(engine=eng, llm_client=llm)

    await asyncio.gather(
        svc.scan_file("AA", "a.md", "agent"),
        svc.scan_file("BB", "b.md", "agent"),
    )

    # Two non-overlapping intervals: second.entry >= first.exit.
    assert len(llm.entry_exit) == 2
    e1, e2 = sorted(llm.entry_exit, key=lambda t: t[0])
    assert e2[0] >= e1[1] - 1e-6  # tiny floating slack


@pytest.mark.asyncio
async def test_get_daily_usage_aggregates_today() -> None:
    eng = _engine_with_settings(budget=5)
    llm = _MockLLMClient(risk_score=10)
    svc = ScanService(engine=eng, llm_client=llm)
    await svc.scan_file("p", "p.md", "agent")
    await svc.scan_file("q", "q.md", "agent")

    usage = await svc.get_daily_usage()
    assert usage["used"] == 2
    assert usage["budget"] == 5
    assert usage["cost_cents"] >= 2
    assert usage["enabled"] is True
