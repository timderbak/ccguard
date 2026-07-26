"""ТЗ-08: three-framework taxonomy + crosswalk + detector binding + honest map.

Acceptance criteria 1–9 (AC10 — engines untouched — is the full ТЗ-01..07
regression, run separately). The headline is AC4: the coverage paradox —
AML.T0051 / ASI01 (IPI) are covered by a CORRELATION detector, not an indicator.
"""
from __future__ import annotations

import pytest
from sqlalchemy.exc import IntegrityError
from sqlmodel import Session, select

from ccguard.server.db.models import (
    Detector,
    DetectorTechniqueMapping,
    IndicatorTechniqueMapping,
    Technique,
    TechniqueCrosswalk,
)
from ccguard.server.db.session import init_db, make_engine
from ccguard.server.services import (
    atlas_seed_service,
    coverage_service,
    indicator_seed_service,
    taxonomy_seed_service,
)

DETECTOR_KEYS = {
    "staging_chain",
    "exfil_sequence",
    "external_trigger",
    "rug_pull_tofu",
    "heartbeat_silent",
    "slow_chain",
    "ai_trigger_escalation",
    "fleet_campaign",
    "toxic_flow",
    "memory_baseline",
    "sandbox_baseline",
    "automemory_baseline",
}


def _engine(tmp_path):
    eng = make_engine(f"sqlite:///{tmp_path}/tz08.db")
    init_db(eng)
    return eng


def _load_all(s: Session) -> None:
    """Load every seed exactly as lifespan does."""
    indicator_seed_service.load_seed(s)
    atlas_seed_service.load_atlas_seed(s)
    atlas_seed_service.migrate_indicator_techniques(s)
    taxonomy_seed_service.load_crosswalk_seed(s)
    taxonomy_seed_service.load_detector_seed(s)


# --- AC1: three frameworks, idempotent, in_scope set -------------------------
def test_three_frameworks_loaded_idempotently(tmp_path) -> None:
    eng = _engine(tmp_path)
    with Session(eng) as s:
        atlas_seed_service.load_atlas_seed(s)
        again = atlas_seed_service.load_atlas_seed(s)  # double start
        techs = s.exec(select(Technique)).all()
    frameworks = {t.framework for t in techs}
    assert {"atlas", "attack", "owasp"} == frameworks  # all three, exactly
    assert again == 0  # no duplicates on second start
    assert any(not t.in_scope for t in techs)  # in_scope discriminator present
    assert {t.technique_id for t in techs if t.framework == "owasp"} >= {
        f"ASI{i:02d}" for i in range(1, 11)
    }  # full ASI01..ASI10


# --- AC2: out-of-scope marked + excluded from gaps ---------------------------
def test_out_of_scope_not_in_gaps(tmp_path) -> None:
    eng = _engine(tmp_path)
    with Session(eng) as s:
        _load_all(s)
        uncovered = {t.technique_id for t in coverage_service.techniques_uncovered(s)}
        oos = {t.technique_id for t in s.exec(select(Technique)).all() if not t.in_scope}
    assert oos  # we do load model-internal techniques
    assert oos.isdisjoint(uncovered)  # ...but none of them are "gaps"
    assert "AML.T0020" in oos  # poison-training-data is out of scope
    # ASI06 (Memory & Context Poisoning) БЫЛ честным пробелом; теперь его
    # закрывает detector_key=memory_baseline (TOFU над CLAUDE.md + @import).
    assert "ASI06" not in uncovered  # closed by the memory-baseline detector
    assert "ASI07" in uncovered  # a still-open in-scope agentic gap, shown honestly


# --- AC3: crosswalk works both directions ------------------------------------
def test_crosswalk_both_directions(tmp_path) -> None:
    eng = _engine(tmp_path)
    with Session(eng) as s:
        _load_all(s)
        from_asi = set(coverage_service.crosswalk_for(s, "ASI04"))
        from_attack = set(coverage_service.crosswalk_for(s, "T1195"))
        from_atlas = set(coverage_service.crosswalk_for(s, "AML.T0010"))
    assert {"AML.T0010", "T1195"} <= from_asi
    assert {"ASI04", "AML.T0010"} <= from_attack  # reverse direction resolves
    assert {"ASI04", "T1195"} <= from_atlas


def test_crosswalk_pair_unique(tmp_path) -> None:
    eng = _engine(tmp_path)
    with Session(eng) as s:
        s.add(TechniqueCrosswalk(technique_id_a="ASI04", technique_id_b="T1195"))
        s.commit()
        s.add(TechniqueCrosswalk(technique_id_a="ASI04", technique_id_b="T1195"))
        with pytest.raises(IntegrityError):
            s.commit()


# --- AC4 (HEADLINE): the paradox — IPI covered by detector, not indicator ----
def test_ipi_covered_by_correlation_not_indicator(tmp_path) -> None:
    eng = _engine(tmp_path)
    with Session(eng) as s:
        _load_all(s)
        covered = {t.technique_id for t in coverage_service.techniques_covered(s)}
        uncovered = {t.technique_id for t in coverage_service.techniques_uncovered(s)}
        # AML.T0051 is covered, yet NO indicator points at it — only a detector.
        ipi_indicators = coverage_service.indicators_for_technique(s, "AML.T0051")
        detail = coverage_service.coverage_detail(s, "AML.T0051")
    assert "AML.T0051" in covered  # the fix: IPI is no longer a hole
    assert "ASI01" in covered  # agent goal hijack, same correlation
    assert "AML.T0051" not in uncovered
    assert ipi_indicators == []  # covered purely by correlation
    assert detail["indicators"] == []
    assert {d["detector_key"] for d in detail["detectors"]} >= {
        "staging_chain",
        "external_trigger",
    }
    assert detail["control_types"] == ["DETECT"]


# --- AC5: all detectors registered + bound with control_type=DETECT ----------
def test_all_detectors_registered_and_bound(tmp_path) -> None:
    eng = _engine(tmp_path)
    with Session(eng) as s:
        again_d = taxonomy_seed_service.load_detector_seed(s)  # first load
        second = taxonomy_seed_service.load_detector_seed(s)  # idempotent
        keys = {d.detector_key for d in s.exec(select(Detector)).all()}
        maps = s.exec(select(DetectorTechniqueMapping)).all()
    assert again_d > 0
    assert second == 0  # idempotent
    assert keys == DETECTOR_KEYS  # exactly the registered correlation detectors
    bound = {m.detector_key for m in maps}
    assert bound == DETECTOR_KEYS  # every detector is bound to ≥1 technique
    assert all(m.control_type == "DETECT" for m in maps)  # correlations DETECT


# --- AC6: indicators still cover ATT&CK, with a control_type -----------------
def test_indicators_still_cover_attack_with_control_type(tmp_path) -> None:
    eng = _engine(tmp_path)
    with Session(eng) as s:
        _load_all(s)
        covered = {t.technique_id for t in coverage_service.techniques_covered(s)}
        itm = s.exec(select(IndicatorTechniqueMapping)).all()
    assert "T1552.001" in covered  # credentials-in-files, via indicator (ТЗ-05)
    assert itm  # indicator mappings exist
    assert all(m.control_type for m in itm)  # every mapping carries a control type
    # ТЗ-09 Step 5: path/host indicators SCOPE, dangerous-command indicators PREV.
    assert {m.control_type for m in itm} <= {"SCOPE", "PREV"}
    assert "PREV" in {m.control_type for m in itm}  # dangerous_command → PREV


def test_indicator_mapping_control_type_default(tmp_path) -> None:
    eng = _engine(tmp_path)
    with Session(eng) as s:
        s.add(IndicatorTechniqueMapping(indicator_id=1, technique_id="T1552"))
        s.commit()
        m = s.exec(select(IndicatorTechniqueMapping)).first()
    assert m.control_type == "SCOPE"


# --- AC7: rollup — parent not a gap when a sub-technique is covered ----------
def test_rollup_parent_not_a_gap(tmp_path) -> None:
    eng = _engine(tmp_path)
    with Session(eng) as s:
        _load_all(s)
        covered = {t.technique_id for t in coverage_service.techniques_covered(s)}
        uncovered = {t.technique_id for t in coverage_service.techniques_uncovered(s)}
        detail = coverage_service.coverage_detail(s, "T1552")
    assert "T1552" in covered  # parent rolled up from its sub-techniques
    assert "T1552" not in uncovered
    assert "T1552.001" in detail["covered_by_children"]  # granularity preserved
    assert detail["covered_via_rollup"] is True


# --- AC8: coverage by control type — where we DETECT vs SCOPE ----------------
def test_coverage_by_control_type(tmp_path) -> None:
    eng = _engine(tmp_path)
    with Session(eng) as s:
        _load_all(s)
        by_ct = coverage_service.coverage_by_control_type(s)
    assert by_ct.get("DETECT", 0) > 0  # agentic techniques are DETECT-covered
    assert by_ct.get("SCOPE", 0) > 0  # endpoint artefacts are SCOPE-covered


# --- AC9: coverage_detail — what covers a technique, and how -----------------
def test_coverage_detail_indicator_side(tmp_path) -> None:
    eng = _engine(tmp_path)
    with Session(eng) as s:
        _load_all(s)
        detail = coverage_service.coverage_detail(s, "T1552.001")
    assert detail["found"] is True
    assert detail["covered"] is True
    assert detail["indicators"]  # covered by ≥1 indicator
    assert "SCOPE" in detail["control_types"]


def test_coverage_detail_unknown_technique(tmp_path) -> None:
    eng = _engine(tmp_path)
    with Session(eng) as s:
        _load_all(s)
        detail = coverage_service.coverage_detail(s, "NOPE.T9999")
    assert detail["found"] is False


# --- detector/mapping uniqueness (schema guards) ----------------------------
def test_detector_key_unique(tmp_path) -> None:
    eng = _engine(tmp_path)
    with Session(eng) as s:
        s.add(Detector(detector_key="staging_chain", name="x"))
        s.commit()
        s.add(Detector(detector_key="staging_chain", name="y"))
        with pytest.raises(IntegrityError):
            s.commit()


def test_detector_mapping_pair_unique(tmp_path) -> None:
    eng = _engine(tmp_path)
    with Session(eng) as s:
        s.add(DetectorTechniqueMapping(
            detector_key="staging_chain", technique_id="ASI01", framework="owasp"))
        s.commit()
        s.add(DetectorTechniqueMapping(
            detector_key="staging_chain", technique_id="ASI01", framework="owasp"))
        with pytest.raises(IntegrityError):
            s.commit()
