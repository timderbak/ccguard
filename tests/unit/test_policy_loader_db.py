"""PolicyLoader: DB-backed, with file bootstrap on empty DB."""

from __future__ import annotations

from pathlib import Path

import pytest
from sqlmodel import Session, SQLModel, create_engine

from ccguard.server.db.models import PolicyVersion
from ccguard.server.policy_loader import PolicyLoader


_INITIAL_YAML = """\
meta:
  schema_version: 1
  revision: 1
  updated_at: '2026-01-01T00:00:00Z'
hooks:
  severity: warn
  allowlist_commands: []
  deny_unknown: true
"""


def _make_engine() -> tuple[object, Session]:
    eng = create_engine("sqlite://")
    SQLModel.metadata.create_all(eng)
    return eng, Session(eng)


def test_loader_bootstraps_from_file_when_db_empty(tmp_path: Path) -> None:
    eng, sess = _make_engine()
    f = tmp_path / "policy.yaml"
    f.write_text(_INITIAL_YAML)
    loader = PolicyLoader(file_path=f, engine=eng)
    pol, etag = loader.load_with_etag(sess)
    assert pol.meta.revision == 1
    assert etag == '"rev-1"'
    rows = list(sess.exec(PolicyVersion.__table__.select()))  # type: ignore[attr-defined]
    assert len(rows) == 1


def test_loader_reads_from_db_when_present(tmp_path: Path) -> None:
    eng, sess = _make_engine()
    sess.add(
        PolicyVersion(
            revision=7,
            status="published",
            yaml_text=_INITIAL_YAML.replace("revision: 1", "revision: 7"),
            created_by="admin",
        )
    )
    sess.commit()
    f = tmp_path / "policy.yaml"
    f.write_text(_INITIAL_YAML)  # different revision; ignored
    loader = PolicyLoader(file_path=f, engine=eng)
    pol, etag = loader.load_with_etag(sess)
    assert pol.meta.revision == 7
    assert etag == '"rev-7"'


def test_loader_returns_none_if_no_db_and_no_file() -> None:
    eng, sess = _make_engine()
    loader = PolicyLoader(file_path=Path("/nonexistent"), engine=eng)
    with pytest.raises(FileNotFoundError):
        loader.load_with_etag(sess)
