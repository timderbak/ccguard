"""Маркер версии справочников + кеш разбора сид-YAML.

Оба механизма пропускают повторную работу при старте. Главный риск здесь —
пропустить работу, которую делать БЫЛО нужно: если маркер не заметит правку
сид-файла, сервер молча продолжит жить на старых справочниках, а обновление
детекта не доедет. Поэтому основное, что проверяется, — инвалидация.
"""
from __future__ import annotations

from pathlib import Path

import pytest
import yaml
from sqlmodel import Session

from ccguard.server.db.session import init_db, make_engine
from ccguard.server.services import seed_marker, seed_yaml_cache


def _engine():
    eng = make_engine("sqlite://")
    init_db(eng)
    return eng


# --- маркер версии справочников ---------------------------------------------


def test_fresh_db_is_not_current():
    # На пустой БД маркера нет → сиды обязаны отработать.
    eng = _engine()
    with Session(eng) as s:
        assert seed_marker.is_current(s) is False


def test_mark_then_current():
    eng = _engine()
    with Session(eng) as s:
        seed_marker.mark_current(s)
        assert seed_marker.is_current(s) is True


def test_digest_changes_when_seed_file_changes(tmp_path: Path):
    # Ключевой инвариант: правка справочника обязана менять отпечаток, иначе
    # обновление детект-правил не доедет до боевой БД.
    for name in ("threat_indicators_seed.yaml", "techniques_seed.yaml",
                 "technique_crosswalk_seed.yaml", "detector_mappings_seed.yaml",
                 "chain_scenarios_seed.yaml"):
        (tmp_path / name).write_text("items: []\n")
    before = seed_marker.reference_digest(tmp_path)
    (tmp_path / "threat_indicators_seed.yaml").write_text("items: [{a: 1}]\n")
    after = seed_marker.reference_digest(tmp_path)
    assert before != after


def test_digest_stable_for_same_content(tmp_path: Path):
    (tmp_path / "threat_indicators_seed.yaml").write_text("items: []\n")
    a = seed_marker.reference_digest(tmp_path)
    b = seed_marker.reference_digest(tmp_path)
    assert a == b


def test_missing_files_still_produce_digest(tmp_path: Path):
    # Пустой каталог: не падаем, а даём отпечаток «файлов нет» — он отличается
    # от отпечатка с файлами, поэтому появление файлов запустит сиды.
    empty = seed_marker.reference_digest(tmp_path)
    (tmp_path / "threat_indicators_seed.yaml").write_text("items: [{a: 1}]\n")
    assert seed_marker.reference_digest(tmp_path) != empty


def test_stale_marker_detected():
    # Маркер от ДРУГОГО состава файлов не должен считаться актуальным.
    eng = _engine()
    with Session(eng) as s:
        seed_marker.mark_current(s, digest="deadbeef")
        assert seed_marker.is_current(s) is False


# --- кеш разбора YAML --------------------------------------------------------


def test_cache_returns_parsed_content(tmp_path: Path):
    f = tmp_path / "x.yaml"
    f.write_text(yaml.safe_dump({"items": [1, 2, 3]}))
    seed_yaml_cache.clear()
    assert seed_yaml_cache.load_yaml(f) == {"items": [1, 2, 3]}


def test_cache_hit_returns_same_object(tmp_path: Path):
    f = tmp_path / "x.yaml"
    f.write_text(yaml.safe_dump({"items": [1]}))
    seed_yaml_cache.clear()
    first = seed_yaml_cache.load_yaml(f)
    second = seed_yaml_cache.load_yaml(f)
    assert first is second  # именно кеш, а не повторный разбор


def test_cache_invalidated_when_file_changes(tmp_path: Path):
    # Тот же риск, что и у маркера: устаревший кеш = сервер на старых данных.
    import os

    f = tmp_path / "x.yaml"
    f.write_text(yaml.safe_dump({"items": [1]}))
    seed_yaml_cache.clear()
    assert seed_yaml_cache.load_yaml(f) == {"items": [1]}

    f.write_text(yaml.safe_dump({"items": [1, 2]}))
    # гарантируем различимый mtime (файловые системы с грубым разрешением)
    st = f.stat()
    os.utime(f, ns=(st.st_atime_ns, st.st_mtime_ns + 1_000_000))
    assert seed_yaml_cache.load_yaml(f) == {"items": [1, 2]}


def test_missing_file_raises_oserror(tmp_path: Path):
    # Ошибку не кешируем и не глотаем — сид-загрузчики сами её обрабатывают.
    seed_yaml_cache.clear()
    with pytest.raises(OSError):
        seed_yaml_cache.load_yaml(tmp_path / "нет-такого.yaml")


def test_broken_yaml_raises_and_is_not_cached(tmp_path: Path):
    f = tmp_path / "bad.yaml"
    f.write_text("{ сломано: : :")
    seed_yaml_cache.clear()
    with pytest.raises(yaml.YAMLError):
        seed_yaml_cache.load_yaml(f)
    # починили — следующий вызов обязан прочитать заново, а не отдать ошибку
    f.write_text(yaml.safe_dump({"ok": True}))
    import os
    st = f.stat()
    os.utime(f, ns=(st.st_atime_ns, st.st_mtime_ns + 1_000_000))
    assert seed_yaml_cache.load_yaml(f) == {"ok": True}


def test_different_files_cached_separately(tmp_path: Path):
    a = tmp_path / "a.yaml"
    a.write_text(yaml.safe_dump({"n": "a"}))
    b = tmp_path / "b.yaml"
    b.write_text(yaml.safe_dump({"n": "b"}))
    seed_yaml_cache.clear()
    assert seed_yaml_cache.load_yaml(a) == {"n": "a"}
    assert seed_yaml_cache.load_yaml(b) == {"n": "b"}
