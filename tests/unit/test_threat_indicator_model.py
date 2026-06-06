"""ТЗ-05: ThreatIndicator table — schema + composite uniqueness.

The store is a REFERENCE catalog of detection inputs (indicators), distinct from
FindingRecord (detection events). This file proves the table stands up and the
(indicator_type, value, source) composite is unique per source — so the same
path attested by two sources is two rows, not a conflict.
"""
from __future__ import annotations

import pytest
from sqlalchemy.exc import IntegrityError
from sqlmodel import Session, select

from ccguard.server.db.models import ThreatIndicator
from ccguard.server.db.session import init_db, make_engine


def _engine(tmp_path):
    eng = make_engine(f"sqlite:///{tmp_path}/ti.db")
    init_db(eng)
    return eng


def _ind(**kw) -> ThreatIndicator:
    base = dict(
        indicator_type="sensitive_path",
        value="~/.aws/credentials",
        value_kind="exact",
        source="os-standard",
        technique="T1552.001",
        tactic="credential-access",
        weight=5.0,
        platform_relevant=True,
        status="active",
        enabled=True,
        description="AWS credentials",
    )
    base.update(kw)
    return ThreatIndicator(**base)


def test_table_create_and_insert(tmp_path) -> None:
    eng = _engine(tmp_path)
    with Session(eng) as s:
        s.add(_ind())
        s.commit()
        rows = s.exec(select(ThreatIndicator)).all()
    assert len(rows) == 1
    assert rows[0].indicator_type == "sensitive_path"
    assert rows[0].source == "os-standard"


def test_same_type_value_source_is_unique(tmp_path) -> None:
    eng = _engine(tmp_path)
    with Session(eng) as s:
        s.add(_ind())
        s.commit()
        s.add(_ind())  # exact duplicate triple
        with pytest.raises(IntegrityError):
            s.commit()


def test_same_path_different_source_allowed(tmp_path) -> None:
    """AC3: the same path attested by two sources = two rows."""
    eng = _engine(tmp_path)
    with Session(eng) as s:
        s.add(_ind(source="os-standard"))
        s.add(_ind(source="atomic-red-team", technique="T1552.001"))
        s.commit()
        rows = s.exec(
            select(ThreatIndicator).where(
                ThreatIndicator.value == "~/.aws/credentials"
            )
        ).all()
    assert {r.source for r in rows} == {"os-standard", "atomic-red-team"}
