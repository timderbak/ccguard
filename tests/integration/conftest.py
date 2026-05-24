"""Фикстуры для интеграционных тестов сервера: TestClient с in-memory SQLite."""

from __future__ import annotations

from collections.abc import Iterator
from datetime import UTC, datetime
from pathlib import Path

import pytest
import yaml
from fastapi.testclient import TestClient

from ccguard.schemas import Policy, PolicyMeta
from ccguard.server.config import ServerConfig, TokenEntry
from ccguard.server.db.session import init_db, make_engine
from ccguard.server.main import create_app
from ccguard.server.policy_loader import PolicyLoader

VALID_TOKEN = "test-token-abc"


def _write_minimal_policy(path: Path, revision: int = 1) -> Policy:
    policy = Policy(meta=PolicyMeta(revision=revision, updated_at=datetime.now(UTC)))
    path.write_text(yaml.safe_dump(policy.model_dump(mode="json"), sort_keys=False))
    return policy


@pytest.fixture
def policy_file(tmp_path: Path) -> Path:
    p = tmp_path / "policy.yaml"
    _write_minimal_policy(p, revision=1)
    return p


@pytest.fixture
def client(tmp_path: Path, policy_file: Path) -> Iterator[TestClient]:
    db_path = tmp_path / "test.db"
    cfg = ServerConfig(
        tokens=[TokenEntry(value=VALID_TOKEN, label="test")],
        policy_path=str(policy_file),
        db_url=f"sqlite:///{db_path}",
    )

    app = create_app()
    # Подменяем lifespan-инициализацию: TestClient запускает lifespan, но мы
    # хотим явно подсунуть свою конфигурацию.
    engine = make_engine(cfg.db_url)
    init_db(engine)
    app.state.config = cfg
    app.state.engine = engine
    app.state.policy_loader = PolicyLoader(file_path=policy_file, engine=engine)

    with TestClient(app) as c:
        # Дополнительная перезапись после lifespan — lifespan может пересчитать
        # state из env. Гарантируем тестовые значения.
        c.app.state.config = cfg  # type: ignore[attr-defined]
        c.app.state.engine = engine  # type: ignore[attr-defined]
        c.app.state.policy_loader = PolicyLoader(file_path=policy_file, engine=engine)  # type: ignore[attr-defined]
        yield c


@pytest.fixture
def auth_headers() -> dict[str, str]:
    return {"X-CCGuard-Token": VALID_TOKEN}
