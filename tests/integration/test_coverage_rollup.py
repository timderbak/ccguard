"""ТЗ-06 fix: sub-technique coverage rolls up to parent; model-level techniques
are marked out-of-scope so they don't masquerade as honest coverage gaps."""
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


def _active_indicator_for(s: Session, technique_id: str) -> None:
    ind = ThreatIndicator(
        indicator_type="sensitive_path", value=f"v/{technique_id}", value_kind="exact",
        source="os-standard", status="active", enabled=True,
    )
    s.add(ind)
    s.commit()
    s.refresh(ind)
    s.add(IndicatorTechniqueMapping(indicator_id=ind.id, technique_id=technique_id))
    s.commit()


def test_parent_covered_when_subtechnique_covered(tmp_path) -> None:
    eng = _engine(tmp_path)
    with Session(eng) as s:
        s.add(AtlasTechnique(technique_id="T1552", framework="attack",
                             name="Unsecured Credentials", tactic="credential-access",
                             parent_technique=None))
        s.add(AtlasTechnique(technique_id="T1552.001", framework="attack",
                             name="Credentials In Files", tactic="credential-access",
                             parent_technique="T1552"))
        s.commit()
        _active_indicator_for(s, "T1552.001")  # only the SUB-technique is covered

        covered = {t.technique_id for t in coverage_service.techniques_covered(s)}
        uncovered = {t.technique_id for t in coverage_service.techniques_uncovered(s)}
    assert "T1552.001" in covered
    assert "T1552" in covered          # rollup: parent covered via its child
    assert "T1552" not in uncovered    # and therefore NOT a gap


def test_out_of_scope_excluded_from_gaps(tmp_path) -> None:
    eng = _engine(tmp_path)
    with Session(eng) as s:
        # model-level technique an endpoint EDR can't cover → out of scope
        s.add(AtlasTechnique(technique_id="AML.T0024", framework="atlas",
                             name="Exfiltration via ML Inference API",
                             tactic="exfiltration", in_scope=False))
        # an in-scope technique with no indicator → a real gap
        s.add(AtlasTechnique(technique_id="AML.T0051", framework="atlas",
                             name="LLM Prompt Injection", tactic="initial-access",
                             in_scope=True))
        s.commit()
        uncovered = {t.technique_id for t in coverage_service.techniques_uncovered(s)}
    assert "AML.T0024" not in uncovered  # out-of-scope is not a gap
    assert "AML.T0051" in uncovered      # in-scope, no indicator → honest gap


def test_coverage_by_tactic_respects_rollup_and_scope(tmp_path) -> None:
    eng = _engine(tmp_path)
    with Session(eng) as s:
        s.add(AtlasTechnique(technique_id="T1552", framework="attack",
                             name="Unsecured Credentials", tactic="credential-access",
                             parent_technique=None))
        s.add(AtlasTechnique(technique_id="T1552.001", framework="attack",
                             name="Credentials In Files", tactic="credential-access",
                             parent_technique="T1552"))
        s.add(AtlasTechnique(technique_id="AML.T0024", framework="atlas",
                             name="Exfil via ML API", tactic="credential-access",
                             in_scope=False))  # excluded from totals
        s.commit()
        _active_indicator_for(s, "T1552.001")
        by_tactic = coverage_service.coverage_by_tactic(s)
    ca = by_tactic["credential-access"]
    assert ca["total"] == 2       # T1552 + T1552.001; out-of-scope AML.T0024 excluded
    assert ca["covered"] == 2     # both covered via rollup
