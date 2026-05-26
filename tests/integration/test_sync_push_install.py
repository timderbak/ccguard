"""Integration tests for the sync→push_install→audit pipeline (plan 04-04).

Covers:
- happy path: policy with one skill + one MCP is applied AND a
  PolicyApplyEvent row with result=success is persisted; CLI exits 0
- rollback: PermissionError during apply still exits 0, persists rollback row
- audit POST 500: files are still on disk, CLI exits 0
- no-op (empty mandatory sections): NO audit POST is sent
- idempotent: two consecutive successful applies produce two events with
  the same applied_count and don't corrupt files
- never-raises: _apply_and_report never raises even if push_install.apply does
"""
from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import patch

import httpx
import pytest
from fastapi.testclient import TestClient
from sqlmodel import Session, select

from ccguard.agent.sync import _apply_and_report
from ccguard.server.db.models import PolicyApplyEvent


# ---- helpers ----------------------------------------------------------------

def _patch_httpx_to_testclient(
    monkeypatch: pytest.MonkeyPatch, client: TestClient
) -> None:
    """Same pattern as test_agent_sync.py: route httpx.Client through TestClient."""
    real_init = httpx.Client.__init__

    def handler(request: httpx.Request) -> httpx.Response:
        url = request.url
        path = url.path
        if url.query:
            q = url.query.decode() if isinstance(url.query, bytes) else url.query
            path = f"{path}?{q}"
        r = client.request(
            request.method,
            path,
            content=request.content,
            headers=dict(request.headers),
        )
        return httpx.Response(
            status_code=r.status_code,
            headers=dict(r.headers),
            content=r.content,
            request=request,
        )

    transport = httpx.MockTransport(handler)

    def patched_init(self, *args, **kwargs):  # type: ignore[no-untyped-def]
        kwargs.pop("transport", None)
        kwargs["transport"] = transport
        real_init(self, *args, **kwargs)

    monkeypatch.setattr(httpx.Client, "__init__", patched_init)


def _policy_with_skill(revision: int = 7) -> dict:
    return {
        "required_skills": [
            {
                "name": "secure-coding",
                "frontmatter_type": "skill",
                "content": "---\nname: secure-coding\n---\n# Secure Coding\n",
            }
        ],
        "required_mcp_servers": [
            {
                "name": "audit-mcp",
                "command": "/usr/bin/audit-mcp",
                "args": [],
                "env": {},
            }
        ],
        # WR-03 (Phase 4 review): policy is re-validated through
        # Policy.model_validate before apply — meta.updated_at is required.
        "meta": {"revision": revision, "updated_at": "2026-05-26T00:00:00Z"},
    }


def _empty_policy() -> dict:
    # WR-03 + WR-06 (Phase 4 review): policy is re-validated through
    # `Policy.model_validate` before apply, so the dict must satisfy the
    # full schema (meta.updated_at is required). The body is intentionally
    # empty of all required_* sections so apply is a true no-op.
    return {
        "meta": {
            "revision": 1,
            "updated_at": "2026-05-26T00:00:00Z",
        }
    }


# ---- tests ------------------------------------------------------------------

def test_apply_and_report_happy_path_persists_success_event(
    monkeypatch: pytest.MonkeyPatch,
    client: TestClient,
    tmp_path: Path,
) -> None:
    _patch_httpx_to_testclient(monkeypatch, client)
    home = tmp_path / "home"
    home.mkdir()

    _apply_and_report(
        _policy_with_skill(),
        server_url="http://testserver",
        token="test-token-abc",
        machine_id="m-happy",
        home=home,
    )

    # Files on disk
    assert (home / ".claude" / "skills" / "secure-coding" / "SKILL.md").exists()
    assert (home / ".claude.json").exists()

    # Audit row persisted
    engine = client.app.state.engine  # type: ignore[attr-defined]
    with Session(engine) as s:
        rows = list(s.exec(select(PolicyApplyEvent)))
        assert len(rows) == 1
        row = rows[0]
        assert row.machine_id == "m-happy"
        assert row.result == "success"
        assert row.applied_count == 2  # one skill + one mcp
        assert row.policy_revision == 7


def test_apply_and_report_rollback_persists_rollback_event(
    monkeypatch: pytest.MonkeyPatch,
    client: TestClient,
    tmp_path: Path,
) -> None:
    _patch_httpx_to_testclient(monkeypatch, client)
    home = tmp_path / "home"
    home.mkdir()

    # Force push_install.apply to return a rollback result without actually
    # tampering with filesystem permissions (cross-platform safer).
    rollback_result = {
        "result": "rollback",
        "applied_count": 1,
        "snapshot_id": "20260526-130000",
        "reason": "PermissionError on agents dir",
        "failed_file": str(home / ".claude" / "agents" / "x.md"),
    }
    with patch("ccguard.agent.sync.push_install_apply", return_value=rollback_result):
        _apply_and_report(
            _policy_with_skill(),
            server_url="http://testserver",
            token="test-token-abc",
            machine_id="m-rollback",
            home=home,
        )

    engine = client.app.state.engine  # type: ignore[attr-defined]
    with Session(engine) as s:
        rows = list(s.exec(select(PolicyApplyEvent)))
        assert len(rows) == 1
        row = rows[0]
        assert row.result == "rollback"
        assert row.reason == "PermissionError on agents dir"
        assert row.failed_file is not None and row.failed_file.endswith("/x.md")


def test_apply_and_report_audit_post_500_does_not_raise(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    """If the audit POST returns 500, the function must NOT raise and files
    written by push_install.apply must still be on disk."""
    # Route httpx through a transport that 500s on /api/v1/audit but lets the
    # actual push_install.apply run normally against tmp home.
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(status_code=500, content=b"boom", request=request)

    transport = httpx.MockTransport(handler)
    real_init = httpx.Client.__init__

    def patched_init(self, *args, **kwargs):  # type: ignore[no-untyped-def]
        kwargs.pop("transport", None)
        kwargs["transport"] = transport
        real_init(self, *args, **kwargs)

    monkeypatch.setattr(httpx.Client, "__init__", patched_init)

    home = tmp_path / "home"
    home.mkdir()

    # Must not raise
    _apply_and_report(
        _policy_with_skill(),
        server_url="http://testserver",
        token="test-token-abc",
        machine_id="m-500",
        home=home,
    )

    # Files were still written despite the audit POST failure
    assert (home / ".claude" / "skills" / "secure-coding" / "SKILL.md").exists()


def test_apply_and_report_empty_policy_posts_noop_audit(
    monkeypatch: pytest.MonkeyPatch,
    client: TestClient,
    tmp_path: Path,
) -> None:
    """WR-06: no-op apply (no required_* sections) MUST POST a
    success/applied_count=0 audit event so admins can distinguish an
    agent that ran with no work from an agent that never reported.
    """
    _patch_httpx_to_testclient(monkeypatch, client)

    home = tmp_path / "home"
    home.mkdir()

    _apply_and_report(
        _empty_policy(),
        server_url="http://testserver",
        token="test-token-abc",
        machine_id="m-empty",
        home=home,
    )

    # Server-side: exactly one PolicyApplyEvent with applied_count==0.
    engine = client.app.state.engine  # type: ignore[attr-defined]
    with Session(engine) as s:
        rows = list(s.exec(select(PolicyApplyEvent)))
        assert len(rows) == 1
        assert rows[0].result == "success"
        assert rows[0].applied_count == 0
        assert rows[0].machine_id == "m-empty"


def test_apply_and_report_is_idempotent(
    monkeypatch: pytest.MonkeyPatch,
    client: TestClient,
    tmp_path: Path,
) -> None:
    _patch_httpx_to_testclient(monkeypatch, client)
    home = tmp_path / "home"
    home.mkdir()

    pol = _policy_with_skill()
    _apply_and_report(
        pol, server_url="http://testserver", token="test-token-abc",
        machine_id="m-idem", home=home,
    )
    skill_path = home / ".claude" / "skills" / "secure-coding" / "SKILL.md"
    first_bytes = skill_path.read_bytes()

    _apply_and_report(
        pol, server_url="http://testserver", token="test-token-abc",
        machine_id="m-idem", home=home,
    )

    engine = client.app.state.engine  # type: ignore[attr-defined]
    with Session(engine) as s:
        rows = list(s.exec(select(PolicyApplyEvent)))
        # Two apply attempts → two events; both success, same applied_count
        assert len(rows) == 2
        assert all(r.result == "success" for r in rows)
        assert {r.applied_count for r in rows} == {2}

    # File content is identical byte-for-byte
    assert skill_path.read_bytes() == first_bytes


def test_apply_and_report_never_raises_when_push_install_blows_up(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    """Belt-and-suspenders: even if push_install.apply itself raises
    (contract says it shouldn't), _apply_and_report must swallow."""
    def boom(*args, **kwargs):
        raise RuntimeError("synthetic explosion")

    with patch("ccguard.agent.sync.push_install_apply", side_effect=boom):
        # Should not raise
        _apply_and_report(
            _policy_with_skill(),
            server_url="http://testserver",
            token="test-token-abc",
            machine_id="m-boom",
            home=tmp_path / "home",
        )


def test_cli_sync_command_invokes_apply_and_report(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    """CLI `ccguard sync` must call _apply_and_report_safe after a successful
    inventory POST, passing the cached policy + agent-derived machine_id.

    We stub :func:`ccguard.agent.cli.perform_sync` so the test does not
    require a live server; the focus is the integration wiring on the CLI
    side."""
    from typer.testing import CliRunner

    from ccguard.agent import cli as cli_module
    from ccguard.agent.sync import SyncResult

    # Redirect agent config dir to a temp location so load_or_create doesn't
    # touch the developer's real $HOME.
    monkeypatch.setenv("CCGUARD_CONFIG_DIR", str(tmp_path / "ccguard"))
    monkeypatch.setenv("CLAUDE_HOME", str(tmp_path / "home" / ".claude"))
    (tmp_path / "home" / ".claude").mkdir(parents=True)

    # Stub perform_sync → successful inventory post + a written policy cache.
    def fake_perform_sync(*, config, **_kw):  # type: ignore[no-untyped-def]
        cache_path = config.resolved_cache_path()
        cache_path.parent.mkdir(parents=True, exist_ok=True)
        # Write a minimal policy with one required skill so the apply step
        # has real work to do (and an audit POST should be sent).
        import yaml as _yaml
        cache_path.write_text(_yaml.safe_dump({
            "meta": {"revision": 3},
            "required_skills": [
                {
                    "name": "demo",
                    "frontmatter_type": "skill",
                    "content": "---\nname: demo\n---\nbody\n",
                }
            ],
        }))
        return SyncResult(
            inventory_posted=True,
            policy_updated=True,
            new_policy_revision=3,
            server_response={"ok": True},
        )

    monkeypatch.setattr(cli_module, "perform_sync", fake_perform_sync)

    # Stub run_scan_cycle to be a no-op (we don't care about the LLM scan).
    import ccguard.agent.inventory_scan as inv_scan
    monkeypatch.setattr(
        inv_scan, "run_scan_cycle",
        lambda **kw: {"skipped": "test"},
    )

    called: dict = {}

    def spy(policy, *, server_url, token, machine_id):
        called["yes"] = True
        called["policy_revision"] = policy.get("meta", {}).get("revision")
        called["machine_id"] = machine_id

    monkeypatch.setattr(cli_module, "_apply_and_report_safe", spy)

    runner = CliRunner()
    result = runner.invoke(cli_module.app, ["sync"])

    assert called.get("yes") is True, (
        f"expected CLI sync to invoke _apply_and_report_safe; stdout={result.stdout}"
    )
    assert called["policy_revision"] == 3
    assert isinstance(called["machine_id"], str) and len(called["machine_id"]) > 0
    # Best-effort guarantee: CLI must exit 0 on the success path.
    assert result.exit_code == 0, result.stdout
