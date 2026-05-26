"""Apply + snapshot + rollback tests for ccguard.agent.push_install.apply."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from ccguard.agent import push_install
from ccguard.agent.push_install import apply


def _minimal_policy(
    *,
    skills: list[dict] | None = None,
    agents: list[dict] | None = None,
    mcp: list[dict] | None = None,
    blocks: list[dict] | None = None,
) -> dict:
    return {
        "required_skills": skills or [],
        "required_agents": agents or [],
        "required_mcp_servers": mcp or [],
        "managed_claude_md_blocks": blocks or [],
    }


def test_apply_writes_all_four_sections(tmp_path: Path) -> None:
    home = tmp_path / "home"
    home.mkdir()
    policy = _minimal_policy(
        skills=[{"name": "sec", "content": "---\nname: sec\n---\nbody"}],
        agents=[{"name": "scout", "content": "agent body"}],
        mcp=[{"name": "tool", "command": "x"}],
        blocks=[{"id": "rules", "content": "Rules body"}],
    )
    res = apply(policy, home=home, ccguard_root=tmp_path / ".ccguard")
    assert res["result"] == "success"
    assert (home / ".claude" / "skills" / "sec" / "SKILL.md").read_text() == "---\nname: sec\n---\nbody"
    assert (home / ".claude" / "agents" / "scout.md").read_text() == "agent body"
    data = json.loads((home / ".claude.json").read_text())
    assert data["mcpServers"]["tool"]["_managed_by"] == "ccguard"
    claude_md = (home / "CLAUDE.md").read_text()
    assert "<!-- ccguard:managed start rules -->" in claude_md


def test_apply_creates_snapshot_dir(tmp_path: Path) -> None:
    home = tmp_path / "home"
    home.mkdir()
    ccg = tmp_path / ".ccguard"
    res = apply(
        _minimal_policy(skills=[{"name": "s", "content": "x"}]),
        home=home,
        ccguard_root=ccg,
    )
    assert res["result"] == "success"
    snap_root = ccg / "snapshots"
    assert snap_root.is_dir()
    snaps = list(snap_root.iterdir())
    assert len(snaps) == 1
    assert res["snapshot_id"] == snaps[0].name


def test_rollback_on_write_failure_restores_files(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    home = tmp_path / "home"
    home.mkdir()
    # Pre-existing user content in CLAUDE.md
    (home / "CLAUDE.md").write_text("ORIGINAL USER CONTENT\n")
    # Pre-existing ~/.claude.json
    (home / ".claude.json").write_text(json.dumps({"mcpServers": {"u": {"command": "u"}}}))

    # Make writing the second skill fail to trigger rollback after some writes succeeded.
    call_count = {"n": 0}
    real_write = push_install.atomic_write_bytes

    def flaky(path: Path, data: bytes) -> None:
        call_count["n"] += 1
        if call_count["n"] == 2:
            raise PermissionError(f"simulated on {path}")
        real_write(path, data)

    monkeypatch.setattr(push_install, "atomic_write_bytes", flaky)

    res = apply(
        _minimal_policy(
            skills=[
                {"name": "a", "content": "A"},
                {"name": "b", "content": "B"},
            ],
            blocks=[{"id": "rules", "content": "X"}],
        ),
        home=home,
        ccguard_root=tmp_path / ".ccguard",
    )
    assert res["result"] == "rollback"
    assert "PermissionError" in res["reason"]
    assert res["failed_file"]
    assert res["snapshot_id"]
    # User content restored byte-for-byte
    assert (home / "CLAUDE.md").read_text() == "ORIGINAL USER CONTENT\n"
    assert json.loads((home / ".claude.json").read_text()) == {"mcpServers": {"u": {"command": "u"}}}


def test_apply_never_raises(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Best-effort: any exception is caught and returned as rollback dict."""
    home = tmp_path / "home"
    home.mkdir()

    def boom(path: Path, data: bytes) -> None:
        raise RuntimeError("kaboom")

    monkeypatch.setattr(push_install, "atomic_write_bytes", boom)

    # Should NOT raise
    res = apply(
        _minimal_policy(skills=[{"name": "x", "content": "c"}]),
        home=home,
        ccguard_root=tmp_path / ".ccguard",
    )
    assert res["result"] == "rollback"
    assert "kaboom" in res["reason"]


def test_rolling_snapshot_window_of_5(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    home = tmp_path / "home"
    home.mkdir()
    ccg = tmp_path / ".ccguard"

    # Force unique sortable snapshot ids in fast succession
    from ccguard.agent import push_install as pi

    counter = {"n": 0}

    def fake_id() -> str:
        counter["n"] += 1
        return f"20260526-12000{counter['n']:02d}"

    monkeypatch.setattr(pi, "_snapshot_id_now", fake_id)

    for i in range(6):
        res = apply(
            _minimal_policy(skills=[{"name": f"s{i}", "content": str(i)}]),
            home=home,
            ccguard_root=ccg,
        )
        assert res["result"] == "success"

    snaps = sorted(p.name for p in (ccg / "snapshots").iterdir())
    assert len(snaps) == 5
    # Newest 5 retained, oldest (#1) pruned
    assert all(s >= "20260526-1200002" for s in snaps)


def test_snapshot_scope_is_targeted_files_only(tmp_path: Path) -> None:
    """D-2: snapshot must contain only target files, not whole ~/.claude/ tree."""
    home = tmp_path / "home"
    (home / ".claude").mkdir(parents=True)
    # Unrelated file that exists in ~/.claude/ — must NOT be snapshotted.
    (home / ".claude" / "settings.json").write_text('{"theme":"dark"}')
    (home / "CLAUDE.md").write_text("user\n")

    res = apply(
        _minimal_policy(blocks=[{"id": "rules", "content": "x"}]),
        home=home,
        ccguard_root=tmp_path / ".ccguard",
    )
    snap_dir = tmp_path / ".ccguard" / "snapshots" / res["snapshot_id"]
    files = [p.relative_to(snap_dir).as_posix() for p in snap_dir.rglob("*") if p.is_file()]
    assert "CLAUDE.md" in files
    assert "settings.json" not in files
    assert ".claude/settings.json" not in files


def test_managed_manifest_not_created(tmp_path: Path) -> None:
    """D-3: no managed-manifest.json — identification is solely via _managed_by."""
    home = tmp_path / "home"
    home.mkdir()
    apply(
        _minimal_policy(mcp=[{"name": "x", "command": "c"}]),
        home=home,
        ccguard_root=tmp_path / ".ccguard",
    )
    assert not (tmp_path / ".ccguard" / "managed-manifest.json").exists()
    assert not (home / ".ccguard" / "managed-manifest.json").exists()


def test_project_claude_md_not_touched(tmp_path: Path) -> None:
    """D-4: only ~/CLAUDE.md (passed via `home`) is touched."""
    home = tmp_path / "home"
    home.mkdir()
    # Simulate a project-scope CLAUDE.md
    project = tmp_path / "project"
    project.mkdir()
    (project / "CLAUDE.md").write_text("PROJECT CONTENT\n")

    apply(
        _minimal_policy(blocks=[{"id": "rules", "content": "x"}]),
        home=home,
        ccguard_root=tmp_path / ".ccguard",
    )
    assert (project / "CLAUDE.md").read_text() == "PROJECT CONTENT\n"
