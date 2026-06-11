"""P6: the coverage map measures detection REALITY, not editorial intent.

``detector_liveness`` / ``technique_detection_status`` bridge Detector →
FindingRecord so a 'covered' technique whose bound detector never fires reads
as 'armed' (or 'dark' if it regressed), instead of a permanent green badge.
"""
from __future__ import annotations

from datetime import UTC, datetime, timedelta

from sqlmodel import Session

from ccguard.server.db.models import Detector, DetectorTechniqueMapping, FindingRecord
from ccguard.server.db.session import init_db, make_engine
from ccguard.server.services import coverage_service


def _engine(tmp_path):
    eng = make_engine(f"sqlite:///{tmp_path}/cov.db")
    init_db(eng)
    return eng


def _finding(s: Session, rule_id: str, days_ago: float) -> None:
    s.add(
        FindingRecord(
            machine_id="m1",
            rule_id=rule_id,
            severity="critical",
            discovered_at=datetime.now(UTC) - timedelta(days=days_ago),
            payload_json="{}",
        )
    )


def test_armed_when_never_fired(tmp_path):
    with Session(_engine(tmp_path)) as s:
        s.add(Detector(detector_key="exfil_sequence", name="Exfil", rule_ids="ioa.exfil_sequence"))
        s.commit()
        live = coverage_service.detector_liveness(s)
    assert live["exfil_sequence"]["status"] == "armed"
    assert live["exfil_sequence"]["last_fired"] is None


def test_detecting_when_recent_finding(tmp_path):
    with Session(_engine(tmp_path)) as s:
        s.add(Detector(detector_key="exfil_sequence", name="Exfil", rule_ids="ioa.exfil_sequence"))
        _finding(s, "ioa.exfil_sequence", days_ago=1)
        s.commit()
        live = coverage_service.detector_liveness(s)
    assert live["exfil_sequence"]["status"] == "detecting"
    assert live["exfil_sequence"]["last_fired"] is not None


def test_dark_when_only_old_finding(tmp_path):
    with Session(_engine(tmp_path)) as s:
        s.add(Detector(detector_key="exfil_sequence", name="Exfil", rule_ids="ioa.exfil_sequence"))
        _finding(s, "ioa.exfil_sequence", days_ago=90)
        s.commit()
        live = coverage_service.detector_liveness(s)
    assert live["exfil_sequence"]["status"] == "dark"


def test_prefix_match_on_rule_id(tmp_path):
    # detector rule_ids "dangerous.destructive" must match finding "dangerous.destructive/delete"
    with Session(_engine(tmp_path)) as s:
        s.add(Detector(detector_key="destructive", name="Destructive", rule_ids="dangerous.destructive"))
        _finding(s, "dangerous.destructive/delete", days_ago=2)
        s.commit()
        live = coverage_service.detector_liveness(s)
    assert live["destructive"]["status"] == "detecting"


def test_technique_status_rollup(tmp_path):
    with Session(_engine(tmp_path)) as s:
        s.add(Detector(detector_key="exfil_sequence", name="Exfil", rule_ids="ioa.exfil_sequence"))
        s.add(
            DetectorTechniqueMapping(
                detector_key="exfil_sequence", technique_id="T1041", framework="attack"
            )
        )
        s.add(
            DetectorTechniqueMapping(
                detector_key="external_trigger", technique_id="AML.T0051", framework="atlas"
            )
        )
        s.add(Detector(detector_key="external_trigger", name="Trigger", rule_ids="ioa.external_trigger"))
        _finding(s, "ioa.exfil_sequence", days_ago=1)
        s.commit()
        status = coverage_service.technique_detection_status(s)
    assert status["T1041"] == "detecting"  # bound detector fired recently
    assert status["AML.T0051"] == "armed"  # bound but never fired
