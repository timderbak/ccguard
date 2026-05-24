"""On startup, env CCGUARD_TOKENS are migrated into AgentToken if table is empty."""

from __future__ import annotations
from sqlmodel import Session, SQLModel, create_engine
from ccguard.server.db.models import AgentToken
from ccguard.server.services.token_service import bootstrap_env_tokens


def test_bootstrap_inserts_when_table_empty():
    engine = create_engine("sqlite://")
    SQLModel.metadata.create_all(engine)
    with Session(engine) as s:
        bootstrap_env_tokens(s, env_tokens=["dev-token", "prod-token"])
        rows = list(s.exec(AgentToken.__table__.select()))  # type: ignore[attr-defined]
        assert len(rows) == 2
        assert all(r.label.startswith("env-bootstrap-") for r in rows)


def test_bootstrap_skips_when_table_nonempty():
    engine = create_engine("sqlite://")
    SQLModel.metadata.create_all(engine)
    with Session(engine) as s:
        s.add(AgentToken(label="existing", token_hash="abc"))
        s.commit()
        bootstrap_env_tokens(s, env_tokens=["dev-token"])
        rows = list(s.exec(AgentToken.__table__.select()))  # type: ignore[attr-defined]
        assert len(rows) == 1
