"""ТЗ-06: AtlasTechnique + IndicatorTechniqueMapping — schema + many-to-many.

Proves the normalized 3-entity model stands up: a technique catalog, a junction
table, and the headline property — one indicator maps to MANY techniques.
"""
from __future__ import annotations

import pytest
from sqlalchemy.exc import IntegrityError
from sqlmodel import Session, select

from ccguard.server.db.models import (
    AtlasTechnique,
    IndicatorTechniqueMapping,
    ThreatIndicator,
)
from ccguard.server.db.session import init_db, make_engine


def _engine(tmp_path):
    eng = make_engine(f"sqlite:///{tmp_path}/atlas.db")
    init_db(eng)
    return eng


def _tech(technique_id="T1552.001", **kw) -> AtlasTechnique:
    base = dict(
        technique_id=technique_id,
        framework="attack",
        name="Credentials In Files",
        tactic="credential-access",
        parent_technique="T1552",
    )
    base.update(kw)
    return AtlasTechnique(**base)


def _indicator(s: Session) -> int:
    ind = ThreatIndicator(
        indicator_type="sensitive_path",
        value="~/.aws/credentials",
        value_kind="exact",
        source="os-standard",
        status="active",
        enabled=True,
    )
    s.add(ind)
    s.commit()
    s.refresh(ind)
    return ind.id


def test_tables_create_and_insert(tmp_path) -> None:
    eng = _engine(tmp_path)
    with Session(eng) as s:
        s.add(_tech())
        s.commit()
        rows = s.exec(select(AtlasTechnique)).all()
    assert len(rows) == 1
    assert rows[0].framework == "attack"


def test_technique_id_unique(tmp_path) -> None:
    eng = _engine(tmp_path)
    with Session(eng) as s:
        s.add(_tech())
        s.commit()
        s.add(_tech())  # duplicate technique_id
        with pytest.raises(IntegrityError):
            s.commit()


def test_mapping_composite_unique(tmp_path) -> None:
    eng = _engine(tmp_path)
    with Session(eng) as s:
        iid = _indicator(s)
        s.add(_tech())
        s.commit()
        s.add(IndicatorTechniqueMapping(indicator_id=iid, technique_id="T1552.001"))
        s.commit()
        s.add(IndicatorTechniqueMapping(indicator_id=iid, technique_id="T1552.001"))
        with pytest.raises(IntegrityError):
            s.commit()


def test_one_indicator_maps_to_many_techniques(tmp_path) -> None:
    """AC3 (headline): ~/.aws/credentials is relevant to BOTH T1552 and T1005."""
    eng = _engine(tmp_path)
    with Session(eng) as s:
        iid = _indicator(s)
        s.add(_tech("T1552", parent_technique=None, name="Unsecured Credentials"))
        s.add(_tech("T1005", parent_technique=None, name="Data from Local System",
                    tactic="collection"))
        s.commit()
        s.add(IndicatorTechniqueMapping(indicator_id=iid, technique_id="T1552"))
        s.add(IndicatorTechniqueMapping(indicator_id=iid, technique_id="T1005"))
        s.commit()
        techs = s.exec(
            select(IndicatorTechniqueMapping.technique_id).where(
                IndicatorTechniqueMapping.indicator_id == iid
            )
        ).all()
    assert set(techs) == {"T1552", "T1005"}
