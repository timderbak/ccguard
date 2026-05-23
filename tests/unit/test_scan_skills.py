"""Скиллы: dir_hash стабильность + детект скриптов."""

from __future__ import annotations

from pathlib import Path

from ccguard.agent.scan.skills import compute_dir_hash, scan_all_skills


def _make_skill(parent: Path, name: str, with_script: bool = False) -> None:
    skill_dir = parent / name
    skill_dir.mkdir(parents=True, exist_ok=True)
    (skill_dir / "SKILL.md").write_text(f"# {name}\n\nDoc body.\n")
    if with_script:
        (skill_dir / "helper.py").write_text("print('hi')\n")


def test_dir_hash_stable(tmp_path: Path) -> None:
    _make_skill(tmp_path, "alpha")
    h1 = compute_dir_hash(tmp_path / "alpha")
    h2 = compute_dir_hash(tmp_path / "alpha")
    assert h1 == h2
    assert len(h1) == 64


def test_dir_hash_changes_on_content_change(tmp_path: Path) -> None:
    _make_skill(tmp_path, "alpha")
    h1 = compute_dir_hash(tmp_path / "alpha")
    (tmp_path / "alpha" / "SKILL.md").write_text("# alpha\n\nModified body.\n")
    h2 = compute_dir_hash(tmp_path / "alpha")
    assert h1 != h2


def test_dir_hash_changes_when_script_added(tmp_path: Path) -> None:
    """§7 BRAINSTORM: подмена скрипта без правки SKILL.md ловится через dir_hash."""
    _make_skill(tmp_path, "alpha")
    h1 = compute_dir_hash(tmp_path / "alpha")
    (tmp_path / "alpha" / "evil.sh").write_text("rm -rf /\n")
    h2 = compute_dir_hash(tmp_path / "alpha")
    assert h1 != h2


def test_scan_all_local_skills(tmp_path: Path) -> None:
    home = tmp_path / "claude"
    (home / "skills").mkdir(parents=True)
    _make_skill(home / "skills", "alpha")
    _make_skill(home / "skills", "beta", with_script=True)
    # Папка без SKILL.md — игнорируется.
    (home / "skills" / "not-a-skill").mkdir()

    skills = scan_all_skills(home)
    by_name = {s.name: s for s in skills}
    assert set(by_name) == {"alpha", "beta"}
    assert by_name["alpha"].origin == "local"
    assert by_name["alpha"].has_referenced_scripts is False
    assert by_name["beta"].has_referenced_scripts is True


def test_scan_plugin_skills(tmp_path: Path) -> None:
    home = tmp_path / "claude"
    plugin_skills_dir = home / "plugins" / "my-plugin" / "skills"
    plugin_skills_dir.mkdir(parents=True)
    _make_skill(plugin_skills_dir, "from-plugin")

    skills = scan_all_skills(home)
    by_name = {s.name: s for s in skills}
    assert "from-plugin" in by_name
    assert by_name["from-plugin"].origin == "plugin"
