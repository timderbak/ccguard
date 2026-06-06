"""ТЗ-06: ATLAS coverage queries — covered / uncovered / by-tactic / remap."""
from __future__ import annotations

from sqlmodel import Session

from ccguard.server.db.models import (
    AtlasTechnique,
    IndicatorTechniqueMapping,
    ThreatIndicator,
)
from ccguard.server.db.session import init_db, make_engine
from ccguard.server.services import coverage_service


def _engine(tmp_path):
    eng = make_engine(f"sqlite:///{tmp_path}/cov.db")
    init_db(eng)
    return eng


def _setup(s: Session) -> dict[str, int]:
    # Two techniques in one tactic; one covered by an active indicator, one not.
    s.add(AtlasTechnique(technique_id="T1552", framework="attack",
                         name="Unsecured Credentials", tactic="credential-access"))
    s.add(AtlasTechnique(technique_id="T1005", framework="attack",
                         name="Data from Local System", tactic="collection"))
    s.add(AtlasTechnique(technique_id="AML.T0024", framework="atlas",
                         name="Exfiltration via ML API", tactic="exfiltration"))
    active = ThreatIndicator(indicator_type="sensitive_path", value="~/.aws/credentials",
                             value_kind="exact", source="os-standard",
                             tactic="credential-access",
                             status="active", enabled=True)
    pending = ThreatIndicator(indicator_type="dangerous_command", value="x",
                              value_kind="regex", source="llm-proposed",
                              status="pending", enabled=True)
    s.add(active)
    s.add(pending)
    s.commit()
    s.refresh(active)
    s.refresh(pending)
    # active indicator covers T1552; pending indicator "covers" T1005 (must NOT count)
    s.add(IndicatorTechniqueMapping(indicator_id=active.id, technique_id="T1552"))
    s.add(IndicatorTechniqueMapping(indicator_id=pending.id, technique_id="T1005"))
    s.commit()
    return {"active": active.id, "pending": pending.id}


def test_techniques_covered_counts_only_active(tmp_path) -> None:
    eng = _engine(tmp_path)
    with Session(eng) as s:
        _setup(s)
        covered = {t.technique_id for t in coverage_service.techniques_covered(s)}
    assert "T1552" in covered          # active indicator
    assert "T1005" not in covered      # only a pending indicator → not covered
    assert "AML.T0024" not in covered  # no indicator at all


def test_techniques_uncovered(tmp_path) -> None:
    eng = _engine(tmp_path)
    with Session(eng) as s:
        _setup(s)
        uncovered = {t.technique_id for t in coverage_service.techniques_uncovered(s)}
    assert "AML.T0024" in uncovered
    assert "T1005" in uncovered        # pending-only mapping doesn't cover it
    assert "T1552" not in uncovered


def test_coverage_by_tactic(tmp_path) -> None:
    eng = _engine(tmp_path)
    with Session(eng) as s:
        _setup(s)
        by_tactic = coverage_service.coverage_by_tactic(s)
    # dict tactic -> {covered, total}
    assert by_tactic["credential-access"]["covered"] == 1
    assert by_tactic["credential-access"]["total"] == 1
    assert by_tactic["collection"]["covered"] == 0
    assert by_tactic["collection"]["total"] == 1
    assert by_tactic["exfiltration"]["covered"] == 0


def test_indicators_for_technique(tmp_path) -> None:
    eng = _engine(tmp_path)
    with Session(eng) as s:
        ids = _setup(s)
        inds = coverage_service.indicators_for_technique(s, "T1552")
    assert [i.id for i in inds] == [ids["active"]]


def test_techniques_for_indicator(tmp_path) -> None:
    eng = _engine(tmp_path)
    with Session(eng) as s:
        ids = _setup(s)
        techs = coverage_service.techniques_for_indicator(s, ids["active"])
    assert {t.technique_id for t in techs} == {"T1552"}


# --- AC8: new technique → auto remap, low confidence -------------------------


def test_remap_creates_auto_mappings_with_low_confidence(tmp_path) -> None:
    eng = _engine(tmp_path)
    with Session(eng) as s:
        _setup(s)
        # A new technique arrives in the SAME tactic as the active indicator.
        s.add(AtlasTechnique(technique_id="T1552.001", framework="attack",
                             name="Credentials In Files", tactic="credential-access",
                             parent_technique="T1552"))
        s.commit()
        created = coverage_service.remap_indicators_to_technique(s, "T1552.001")
        maps = coverage_service.indicators_for_technique(s, "T1552.001")
        auto = [
            m for m in s.exec(
                __import__("sqlmodel").select(IndicatorTechniqueMapping).where(
                    IndicatorTechniqueMapping.technique_id == "T1552.001"
                )
            ).all()
        ]
    assert created >= 1
    assert maps  # the credential-access indicator got mapped by tactic heuristic
    assert all(m.mapping_source == "auto" for m in auto)
    assert all(m.confidence < 1.0 for m in auto)
