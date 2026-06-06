"""ТЗ-04: noise suppression (allowlist) + additive scoring for the staging chain.

The whole point is fewer false positives WITHOUT swallowing real attacks. The
🔒 safety predicate (test_attack_survives_suppression) is the blocking criterion:
if it ever goes red, suppression ate the attack and the ТЗ has failed.
"""
from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta

from sqlmodel import Session, select

from ccguard.server.db.models import FindingRecord, Machine, MachineBaseline
from ccguard.server.services import sequence_service, settings_service
from ccguard.server.services.sequence_constants import (
    STAGING_RULE_ID,
    STAGING_SUPPRESSED_RULE_ID,
)


def _warm(session: Session, machine_id: str) -> None:
    session.add(Machine(machine_id=machine_id, hostname="h"))
    session.add(
        MachineBaseline(
            machine_id=machine_id,
            metric="bash_calls_per_day",
            mean=1.0,
            stdev=0.5,
            sample_count=14,
            baseline_ready=True,
        )
    )
    session.commit()


def _add(
    session: Session,
    machine_id: str,
    *,
    signals: list[str],
    minutes_ago: float,
    session_id: str | None = "A",
) -> None:
    session.add(
        sequence_service.ToolUseEvent(  # type: ignore[attr-defined]
            machine_id=machine_id,
            ts=datetime.now(UTC) - timedelta(minutes=minutes_ago),
            tool_name="Write",
            fingerprint="0123456789abcdef",
            decision="allow",
            result_status="success",
            signals_json=json.dumps(signals),
            session_id=session_id,
        )
    )
    session.commit()


# --- AC1: build/package noise suppressed ------------------------------------


def test_cache_write_is_suppressed(client) -> None:
    """external-read → hidden write whose event is a build cache → suppressed,
    no block/warn finding."""
    engine = client.app.state.engine  # type: ignore[attr-defined]
    with Session(engine) as s:
        _warm(s, "m-cache")
        _add(s, "m-cache", signals=["content.read.external"], minutes_ago=5)
        _add(s, "m-cache", signals=["fs.write.hidden", "fs.write.cache"], minutes_ago=2)
        finding = sequence_service.evaluate_one_staging(s, "m-cache")
    assert finding is not None
    assert finding.rule_id == STAGING_SUPPRESSED_RULE_ID
    assert finding.severity == "info"
    payload = json.loads(finding.payload_json)
    assert payload["suppressed"] is True
    assert payload["suppression_reason"]


def test_vcs_write_is_suppressed(client) -> None:
    engine = client.app.state.engine  # type: ignore[attr-defined]
    with Session(engine) as s:
        _warm(s, "m-vcs")
        _add(s, "m-vcs", signals=["content.read.external"], minutes_ago=5)
        _add(s, "m-vcs", signals=["fs.write.hidden", "fs.write.vcs"], minutes_ago=2)
        finding = sequence_service.evaluate_one_staging(s, "m-vcs")
    assert finding is not None
    assert finding.rule_id == STAGING_SUPPRESSED_RULE_ID


# --- AC2: 🔒 SAFETY PREDICATE — attack survives suppression ------------------


def test_attack_survives_suppression(client) -> None:
    """🔒 BLOCKING: external-read → hidden write to an UNUSUAL path (no cache/vcs
    marker), no egress → stays block, external_trigger=true, NOT suppressed.
    The Confluence/IPI scenario must live through every suppression."""
    engine = client.app.state.engine  # type: ignore[attr-defined]
    with Session(engine) as s:
        _warm(s, "m-attack")
        _add(s, "m-attack", signals=["content.read.external"], minutes_ago=5)
        _add(s, "m-attack", signals=["fs.write.hidden"], minutes_ago=2)  # no marker
        finding = sequence_service.evaluate_one_staging(s, "m-attack")
    assert finding is not None
    assert finding.rule_id == STAGING_RULE_ID
    assert finding.severity == "block"
    payload = json.loads(finding.payload_json)
    assert payload["external_trigger"] is True
    assert payload["suppressed"] is False


def test_full_attack_chain_stays_critical(client) -> None:
    """AC3: external → hidden(unusual) → egress → critical, not lowered."""
    engine = client.app.state.engine  # type: ignore[attr-defined]
    with Session(engine) as s:
        _warm(s, "m-attack-full")
        _add(s, "m-attack-full", signals=["content.read.external"], minutes_ago=9)
        _add(s, "m-attack-full", signals=["fs.write.hidden"], minutes_ago=6)
        _add(s, "m-attack-full", signals=["egress.network_tool"], minutes_ago=3)
        finding = sequence_service.evaluate_one_staging(s, "m-attack-full")
    assert finding is not None
    assert finding.severity == "critical"


# --- AC4: scoring gradation + breakdown -------------------------------------


def test_weak_combo_below_threshold_is_info_not_warn(client) -> None:
    """normal write, no external, no egress → score below warn → info."""
    engine = client.app.state.engine  # type: ignore[attr-defined]
    with Session(engine) as s:
        _warm(s, "m-weak")
        _add(s, "m-weak", signals=["cred.read.aws"], minutes_ago=5)
        _add(s, "m-weak", signals=["fs.write.normal"], minutes_ago=2)
        finding = sequence_service.evaluate_one_staging(s, "m-weak")
    assert finding is not None
    assert finding.severity == "info"
    payload = json.loads(finding.payload_json)
    # additive scoring is explainable
    assert "score" in payload
    assert "score_factors" in payload
    assert "threshold" in payload or "thresholds" in payload


def test_non_external_hidden_stays_warn(client) -> None:
    """AC7: ТЗ-02 behavior preserved — non-external hidden(unusual) → warn."""
    engine = client.app.state.engine  # type: ignore[attr-defined]
    with Session(engine) as s:
        _warm(s, "m-warn")
        _add(s, "m-warn", signals=["cred.read.aws"], minutes_ago=5)
        _add(s, "m-warn", signals=["fs.write.hidden"], minutes_ago=2)
        finding = sequence_service.evaluate_one_staging(s, "m-warn")
    assert finding is not None
    assert finding.severity == "warn"


# --- AC5: suppression is transparent ----------------------------------------


def test_suppressed_match_is_findable(client) -> None:
    engine = client.app.state.engine  # type: ignore[attr-defined]
    with Session(engine) as s:
        _warm(s, "m-find")
        _add(s, "m-find", signals=["content.read.external"], minutes_ago=5)
        _add(s, "m-find", signals=["fs.write.hidden", "fs.write.cache"], minutes_ago=2)
        sequence_service.evaluate_one_staging(s, "m-find")
        rows = s.exec(
            select(FindingRecord).where(
                FindingRecord.rule_id == STAGING_SUPPRESSED_RULE_ID
            )
        ).all()
    assert len(rows) == 1  # suppressed match left a transparent trail


# --- AC6: thresholds tunable from settings ----------------------------------


def test_threshold_from_settings_changes_verdict(client) -> None:
    """Same input, raised block-threshold → verdict drops from block to warn."""
    engine = client.app.state.engine  # type: ignore[attr-defined]
    with Session(engine) as s:
        settings_service.set_setting(s, "staging.threshold.block", "999")
        _warm(s, "m-tune")
        _add(s, "m-tune", signals=["content.read.external"], minutes_ago=5)
        _add(s, "m-tune", signals=["fs.write.hidden"], minutes_ago=2)
        finding = sequence_service.evaluate_one_staging(s, "m-tune")
    assert finding is not None
    # block unreachable now → falls to the next tier down
    assert finding.severity != "block"


# --- AC8: session-scope still holds for the suppression/scoring path ---------


def test_session_scope_preserved_with_scoring(client) -> None:
    engine = client.app.state.engine  # type: ignore[attr-defined]
    with Session(engine) as s:
        _warm(s, "m-scope")
        _add(s, "m-scope", signals=["content.read.external"], minutes_ago=5, session_id="A")
        _add(s, "m-scope", signals=["fs.write.hidden"], minutes_ago=2, session_id="B")
        finding = sequence_service.evaluate_one_staging(s, "m-scope")
    assert finding is None
