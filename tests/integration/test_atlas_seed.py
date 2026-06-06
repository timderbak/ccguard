"""ТЗ-06: ATLAS taxonomy seed loader + ТЗ-05 technique→mapping migration."""
from __future__ import annotations

import yaml
from sqlmodel import Session, select

from ccguard.server.db.models import (
    AtlasTechnique,
    IndicatorTechniqueMapping,
)
from ccguard.server.db.session import init_db, make_engine
from ccguard.server.services import atlas_seed_service, indicator_seed_service


def _engine(tmp_path):
    eng = make_engine(f"sqlite:///{tmp_path}/atlas.db")
    init_db(eng)
    return eng


def _seed_count() -> int:
    path = atlas_seed_service.default_seed_path()
    return len(yaml.safe_load(path.read_text())["techniques"])


def test_atlas_seed_loads(tmp_path) -> None:
    eng = _engine(tmp_path)
    with Session(eng) as s:
        inserted = atlas_seed_service.load_atlas_seed(s)
        rows = s.exec(select(AtlasTechnique)).all()
    assert inserted == _seed_count()
    assert len(rows) == _seed_count()


def test_atlas_seed_idempotent(tmp_path) -> None:
    eng = _engine(tmp_path)
    with Session(eng) as s:
        atlas_seed_service.load_atlas_seed(s)
        again = atlas_seed_service.load_atlas_seed(s)
        total = len(s.exec(select(AtlasTechnique)).all())
    assert again == 0
    assert total == _seed_count()


def test_both_frameworks_present(tmp_path) -> None:
    eng = _engine(tmp_path)
    with Session(eng) as s:
        atlas_seed_service.load_atlas_seed(s)
        fws = {r.framework for r in s.exec(select(AtlasTechnique)).all()}
    assert {"atlas", "attack"} <= fws


def test_missing_seed_returns_zero(tmp_path) -> None:
    eng = _engine(tmp_path)
    with Session(eng) as s:
        n = atlas_seed_service.load_atlas_seed(s, seed_path=tmp_path / "nope.yaml")
    assert n == 0


def test_corrupt_seed_returns_zero(tmp_path) -> None:
    bad = tmp_path / "bad.yaml"
    bad.write_text("{ broken: : : :")
    eng = _engine(tmp_path)
    with Session(eng) as s:
        assert atlas_seed_service.load_atlas_seed(s, seed_path=bad) == 0


# --- AC4: migrate ТЗ-05 technique field → mapping ----------------------------


def test_migration_creates_mappings_from_indicator_technique(tmp_path) -> None:
    eng = _engine(tmp_path)
    with Session(eng) as s:
        indicator_seed_service.load_seed(s)  # ТЗ-05 indicators (with technique)
        atlas_seed_service.load_atlas_seed(s)  # techniques must exist first
        created = atlas_seed_service.migrate_indicator_techniques(s)
        mappings = s.exec(select(IndicatorTechniqueMapping)).all()
    assert created > 0
    assert len(mappings) == created
    assert all(m.mapping_source == "seed" for m in mappings)


def test_migration_idempotent(tmp_path) -> None:
    eng = _engine(tmp_path)
    with Session(eng) as s:
        indicator_seed_service.load_seed(s)
        atlas_seed_service.load_atlas_seed(s)
        atlas_seed_service.migrate_indicator_techniques(s)
        first = len(s.exec(select(IndicatorTechniqueMapping)).all())
        again = atlas_seed_service.migrate_indicator_techniques(s)
        total = len(s.exec(select(IndicatorTechniqueMapping)).all())
    assert again == 0
    assert total == first
