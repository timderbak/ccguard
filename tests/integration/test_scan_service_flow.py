"""Integration tests for ScanService end-to-end flow (Plan 03-03).

Real SQLite + real models; only ``LLMClient.scan_content`` is mocked.

Flows:
1. Three distinct files → 3 ScanResult rows, 3 LLMCallLog rows; findings only
   for risk_score >= 30.
2. Re-scan: scan file A → rescan_file(hash_A) → next scan_file re-issues the
   LLM call; ScanResult.scanned_at advances; finding re-emits if score >= 30.
3. Budget exhaustion mid-batch: budget=2; 3rd new scan raises; cache hit on
   file 1 still succeeds (cache hits bypass budget).
4. Scanner disabled → ScannerDisabledError; no LLMCallLog written.
"""

from __future__ import annotations

import asyncio
import hashlib
from datetime import UTC, datetime

import pytest
from sqlmodel import Session, select

from ccguard.server.db.models import (
    FindingRecord,
    LLMCallLog,
    ScanResult,
    SettingsRecord,
)
from ccguard.server.db.session import init_db, make_engine
from ccguard.server.services.llm_client import ScanOutcome
from ccguard.server.services.scan_service import (
    BudgetExhaustedError,
    ScannerDisabledError,
    ScanService,
)
from ccguard.server.services.settings_service import seed_llm_settings


def _engine(enabled: bool = True, budget: int = 100):
    eng = make_engine("sqlite://")
    init_db(eng)
    with Session(eng) as s:
        seed_llm_settings(s)
        e_row = s.exec(
            select(SettingsRecord).where(SettingsRecord.key == "llm_scanner_enabled")
        ).first()
        e_row.value = "true" if enabled else "false"
        b_row = s.exec(
            select(SettingsRecord).where(SettingsRecord.key == "daily_call_budget")
        ).first()
        b_row.value = str(budget)
        s.commit()
    return eng


class _ScriptedLLM:
    """Mock LLMClient.scan_content returning scripted outcomes per file_path."""

    def __init__(self, script: dict[str, ScanOutcome]) -> None:
        self.script = script
        self.calls: list[tuple[str, str, str]] = []

    async def scan_content(self, content: str, file_path: str, scope: str):
        self.calls.append((content, file_path, scope))
        return self.script[file_path]


def _outcome(score: int, category: str = "benign") -> ScanOutcome:
    return ScanOutcome(
        risk_score=score,
        category=category,
        rationale="rat",
        input_tokens=100,
        output_tokens=20,
        cost_cents=1,
        model="claude-haiku-4-5-20251001",
    )


@pytest.mark.asyncio
async def test_flow_three_files_findings_only_above_threshold() -> None:
    eng = _engine(budget=5)
    llm = _ScriptedLLM(
        {
            "a.md": _outcome(10, "benign"),  # no finding
            "b.md": _outcome(40, "jailbreak"),  # warn
            "c.md": _outcome(80, "data-exfil"),  # critical
        }
    )
    svc = ScanService(engine=eng, llm_client=llm)

    await svc.scan_file("A-content", "a.md", "agent")
    await svc.scan_file("B-content", "b.md", "agent")
    await svc.scan_file("C-content", "c.md", "skill")

    with Session(eng) as s:
        assert len(list(s.exec(select(ScanResult)))) == 3
        assert len(list(s.exec(select(LLMCallLog)))) == 3
        findings = list(s.exec(select(FindingRecord)))
        # Only b.md (warn) and c.md (critical) → 2 findings.
        assert len(findings) == 2
        sev = {f.severity for f in findings}
        assert sev == {"warn", "critical"}
        rules = {f.rule_id for f in findings}
        assert rules == {"llm.scan.jailbreak", "llm.scan.data-exfil"}


@pytest.mark.asyncio
async def test_flow_rescan_invalidates_cache_and_reissues_call() -> None:
    eng = _engine(budget=10)
    llm = _ScriptedLLM({"a.md": _outcome(40, "jailbreak")})
    svc = ScanService(engine=eng, llm_client=llm)

    r1 = await svc.scan_file("A", "a.md", "agent")
    first_scanned_at = r1.scanned_at
    assert len(llm.calls) == 1

    # Cache hit — no new call.
    await svc.scan_file("A", "a.md", "agent")
    assert len(llm.calls) == 1

    # Mark expired.
    file_hash = hashlib.sha256(b"A").hexdigest()
    sentinel = await svc.rescan_file(file_hash)
    assert sentinel is not None

    # Tiny sleep so scanned_at strictly advances on platforms with coarse clocks.
    await asyncio.sleep(0.01)

    # Now re-issue the call.
    r2 = await svc.scan_file("A", "a.md", "agent")
    assert len(llm.calls) == 2
    # scanned_at advances (allow naive-vs-aware tz coercion)
    def _aw(dt: datetime) -> datetime:
        return dt if dt.tzinfo else dt.replace(tzinfo=UTC)

    assert _aw(r2.scanned_at) >= _aw(first_scanned_at)

    # Finding re-emitted.
    with Session(eng) as s:
        findings = list(s.exec(select(FindingRecord)))
        assert len(findings) == 2
        for f in findings:
            assert f.rule_id == "llm.scan.jailbreak"
            assert f.severity == "warn"


@pytest.mark.asyncio
async def test_flow_budget_exhaustion_then_cache_hit_succeeds() -> None:
    eng = _engine(budget=2)
    llm = _ScriptedLLM(
        {
            "a.md": _outcome(10),
            "b.md": _outcome(20),
            "c.md": _outcome(30, "jailbreak"),
        }
    )
    svc = ScanService(engine=eng, llm_client=llm)

    # First two consume the budget.
    await svc.scan_file("A", "a.md", "agent")
    await svc.scan_file("B", "b.md", "agent")

    # Third raises.
    with pytest.raises(BudgetExhaustedError):
        await svc.scan_file("C", "c.md", "agent")

    # Cache hit on file A still works.
    r = await svc.scan_file("A", "a.md", "agent")
    assert r.risk_score == 10
    assert len(llm.calls) == 2  # no new call

    with Session(eng) as s:
        assert len(list(s.exec(select(ScanResult)))) == 2
        assert len(list(s.exec(select(LLMCallLog)))) == 2


@pytest.mark.asyncio
async def test_flow_scanner_disabled_no_llm_call_no_log() -> None:
    eng = _engine(enabled=False)
    llm = _ScriptedLLM({"a.md": _outcome(50)})
    svc = ScanService(engine=eng, llm_client=llm)

    with pytest.raises(ScannerDisabledError):
        await svc.scan_file("A", "a.md", "agent")

    assert llm.calls == []
    with Session(eng) as s:
        assert list(s.exec(select(LLMCallLog))) == []
        assert list(s.exec(select(ScanResult))) == []
        assert list(s.exec(select(FindingRecord))) == []
