"""UI rendering proof for the D-01 severity ladder (Plan 03-06).

These tests insert FindingRecord rows directly into the DB and GET /findings,
asserting the exact Tailwind class strings the badge partial emits per band:

- score > 70  → ``bg-red-600``     (critical)
- 30 ≤ s ≤ 70 → ``bg-amber-600``   (warn)
- score < 30  → ``bg-emerald-600`` (info)
- non-LLM finding (rule_id NOT starting with llm.scan.) → em-dash, no rescan form
"""

from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from sqlmodel import Session

from ccguard.server.db.models import FindingRecord
from ccguard.server.db.session import init_db, make_engine
from ccguard.server.main import create_app
from ccguard.server.policy_loader import PolicyLoader
from ccguard.server.config import ServerConfig, TokenEntry
from ccguard.server.services.auth_service import create_session, hash_password
from ccguard.server.services.settings_service import seed_llm_settings
from ccguard.server.web.csrf import generate_csrf_token

import yaml

from ccguard.schemas import Policy, PolicyMeta


def _setup(tmp_path: Path) -> tuple[TestClient, str, object]:
    policy_path = tmp_path / "policy.yaml"
    policy_path.write_text(
        yaml.safe_dump(
            Policy(meta=PolicyMeta(revision=1, updated_at=datetime.now(UTC))).model_dump(mode="json"),
            sort_keys=False,
        )
    )
    db_path = tmp_path / "badge.db"
    cfg = ServerConfig(
        tokens=[TokenEntry(value="t", label="x")],
        policy_path=str(policy_path),
        db_url=f"sqlite:///{db_path}",
        session_secret="test-secret",
        admin_user="admin",
        admin_password_hash=hash_password("hunter2"),
    )
    app = create_app()
    engine = make_engine(cfg.db_url)
    init_db(engine)
    with Session(engine) as s:
        seed_llm_settings(s)
    app.state.config = cfg
    app.state.engine = engine
    app.state.policy_loader = PolicyLoader(file_path=policy_path, engine=engine)
    client = TestClient(app)
    client.__enter__()
    client.app.state.config = cfg  # type: ignore[attr-defined]
    client.app.state.engine = engine  # type: ignore[attr-defined]
    client.app.state.policy_loader = PolicyLoader(file_path=policy_path, engine=engine)  # type: ignore[attr-defined]
    with Session(engine) as s:
        sid = create_session(s, user_id="admin")
    return client, sid, engine


def _seed_llm_finding(
    engine,
    *,
    severity: str,
    risk_score: int,
    category: str,
    file_hash: str = "abc1234567890",
) -> None:
    now = datetime.now(UTC)
    payload = {
        "file_hash": file_hash,
        "risk_score": risk_score,
        "category": category,
        "rationale": "ui test",
        "scope": "agent",
        "file_path": "/agents/evil.md",
        "model": "claude-haiku-4-5-20251001",
    }
    with Session(engine) as s:
        s.add(
            FindingRecord(
                machine_id="_server",
                inventory_id=None,
                rule_id=f"llm.scan.{category}",
                severity=severity,
                discovered_at=now,
                payload_json=json.dumps(payload),
            )
        )
        s.commit()


def test_critical_score_renders_red(tmp_path: Path) -> None:
    client, sid, engine = _setup(tmp_path)
    try:
        _seed_llm_finding(
            engine,
            severity="critical",
            risk_score=85,
            category="data-exfil",
            file_hash="abc1234567890",
        )
        r = client.get("/findings", cookies={"ccg_session": sid})
        assert r.status_code == 200, r.text
        body = r.content
        assert b"bg-red-600" in body
        assert b"data-exfil" in body
        assert b'hx-post="/admin/scan/abc1234567890/rescan"' in body
        assert "Пересканировать".encode("utf-8") in body
    finally:
        client.__exit__(None, None, None)


def test_warn_score_renders_amber(tmp_path: Path) -> None:
    client, sid, engine = _setup(tmp_path)
    try:
        _seed_llm_finding(
            engine, severity="warn", risk_score=50, category="prompt-injection-template",
        )
        r = client.get("/findings", cookies={"ccg_session": sid})
        assert r.status_code == 200
        assert b"bg-amber-600" in r.content
    finally:
        client.__exit__(None, None, None)


def test_info_score_renders_emerald(tmp_path: Path) -> None:
    """info findings (score<30) are not emitted by the scanner, but the badge
    template renders them defensively when score<30 lands in the row."""
    client, sid, engine = _setup(tmp_path)
    try:
        _seed_llm_finding(
            engine, severity="info", risk_score=15, category="benign",
        )
        r = client.get("/findings", cookies={"ccg_session": sid})
        assert r.status_code == 200
        assert b"bg-emerald-600" in r.content
    finally:
        client.__exit__(None, None, None)


def test_non_llm_row_renders_emdash(tmp_path: Path) -> None:
    """Anomaly findings (rule_id not under llm.scan.) → em-dash columns and no
    'Пересканировать' button."""
    client, sid, engine = _setup(tmp_path)
    try:
        now = datetime.now(UTC)
        with Session(engine) as s:
            s.add(
                FindingRecord(
                    machine_id="laptop-1",
                    inventory_id=None,
                    rule_id="anomaly.bash_calls",
                    severity="warn",
                    discovered_at=now,
                    payload_json=json.dumps({"sigma": 3.5}),
                )
            )
            s.commit()
        r = client.get("/findings", cookies={"ccg_session": sid})
        assert r.status_code == 200
        body = r.content.decode("utf-8")
        # The em-dash appears in the badge AND in the rescan column for non-LLM rows.
        assert "—" in body
        # No rescan form for this row.
        assert "/admin/scan/" not in body or "rescan" not in body.split("anomaly.bash_calls", 1)[1].split("</tr>", 1)[0]
        # No critical/red badge for this single warn-anomaly row.
        assert "bg-red-600" not in body
    finally:
        client.__exit__(None, None, None)
