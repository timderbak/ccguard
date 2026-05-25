"""Unit tests for Plan 03-01 Task 1: extend Severity Literal with 'critical'.

Covers:
- Finding(severity="critical") validates.
- Existing severities {info, warn, block} continue to validate (regression).
- GET /api/v1/findings?severity=critical → 200 (regex accepts critical).
- GET /api/v1/findings?severity=bogus → 422 (regex rejects unknown).
- GET /api/v1/findings?severity={info,warn,block} → 200 (regression).
"""

from __future__ import annotations

from collections.abc import Iterator
from datetime import UTC, datetime
from pathlib import Path

import pytest
import yaml
from fastapi.testclient import TestClient

from ccguard.schemas import Policy, PolicyMeta
from ccguard.schemas.finding import Finding
from ccguard.server.config import ServerConfig, TokenEntry
from ccguard.server.db.session import init_db, make_engine
from ccguard.server.main import create_app
from ccguard.server.policy_loader import PolicyLoader

_VALID_TOKEN = "test-token-severity"


# ---- Schema-level tests ----------------------------------------------------


def test_finding_accepts_critical_severity() -> None:
    f = Finding(
        rule_id="llm.scan.critical",
        severity="critical",
        title="critical leak",
        description="d",
        source="llm_scanner",
        recommendation="r",
    )
    assert f.severity == "critical"


@pytest.mark.parametrize("sev", ["info", "warn", "block"])
def test_finding_accepts_existing_severities(sev: str) -> None:
    f = Finding(
        rule_id="r",
        severity=sev,  # type: ignore[arg-type]
        title="t",
        description="d",
        source="s",
        recommendation="rec",
    )
    assert f.severity == sev


def test_finding_rejects_unknown_severity() -> None:
    with pytest.raises(Exception):
        Finding(
            rule_id="r",
            severity="bogus",  # type: ignore[arg-type]
            title="t",
            description="d",
            source="s",
            recommendation="rec",
        )


# ---- API-level tests -------------------------------------------------------


@pytest.fixture
def _client(tmp_path: Path) -> Iterator[TestClient]:
    policy_path = tmp_path / "policy.yaml"
    policy = Policy(meta=PolicyMeta(revision=1, updated_at=datetime.now(UTC)))
    policy_path.write_text(yaml.safe_dump(policy.model_dump(mode="json"), sort_keys=False))

    db_path = tmp_path / "t.db"
    cfg = ServerConfig(
        tokens=[TokenEntry(value=_VALID_TOKEN, label="test")],
        policy_path=str(policy_path),
        db_url=f"sqlite:///{db_path}",
    )
    app = create_app()
    engine = make_engine(cfg.db_url)
    init_db(engine)
    app.state.config = cfg
    app.state.engine = engine
    app.state.policy_loader = PolicyLoader(file_path=policy_path, engine=engine)
    with TestClient(app) as c:
        c.app.state.config = cfg  # type: ignore[attr-defined]
        c.app.state.engine = engine  # type: ignore[attr-defined]
        c.app.state.policy_loader = PolicyLoader(  # type: ignore[attr-defined]
            file_path=policy_path, engine=engine
        )
        yield c


def _hdr() -> dict[str, str]:
    return {"X-CCGuard-Token": _VALID_TOKEN}


def test_findings_severity_critical_returns_200(_client: TestClient) -> None:
    r = _client.get("/api/v1/findings?severity=critical", headers=_hdr())
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["findings"] == []
    assert body["total"] == 0


def test_findings_severity_bogus_returns_422(_client: TestClient) -> None:
    r = _client.get("/api/v1/findings?severity=bogus", headers=_hdr())
    assert r.status_code == 422


@pytest.mark.parametrize("sev", ["info", "warn", "block"])
def test_findings_existing_severities_still_accepted(_client: TestClient, sev: str) -> None:
    r = _client.get(f"/api/v1/findings?severity={sev}", headers=_hdr())
    assert r.status_code == 200, r.text
