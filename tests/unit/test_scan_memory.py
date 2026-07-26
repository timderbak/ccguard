"""Сканер памяти: находит файлы инструкций и проходит @import-цепочки.

Главное, что проверяется, — не «нашёл CLAUDE.md», а свойства, от которых
зависит ценность:

* @import резолвится относительно файла-родителя и рекурсивно, как в Claude
  Code, — иначе спрятанная за ссылкой инструкция осталась бы невидимой;
* цикл импортов не вешает сканер;
* @-упоминание внутри примера кода НЕ считается импортом (иначе документация
  порождала бы ложные записи);
* содержимое не утекает — наружу идёт только хеш.
"""
from __future__ import annotations

from pathlib import Path

from ccguard.agent.scan import memory as m


def _by_scope(entries):
    return {e.scope: e for e in entries}


def test_finds_claude_md_at_each_level(tmp_path: Path):
    home = tmp_path / "home" / ".claude"
    home.mkdir(parents=True)
    (home / "CLAUDE.md").write_text("user memory")
    proj = tmp_path / "proj"
    proj.mkdir()
    (proj / "CLAUDE.md").write_text("project memory")
    (proj / "CLAUDE.local.md").write_text("local memory")

    entries = m.scan_memory(home, proj, platform="linux")
    scopes = {e.scope for e in entries}
    assert {"user", "project", "project_local"} <= scopes


def test_content_never_leaves_only_hash(tmp_path: Path):
    home = tmp_path / ".claude"
    home.mkdir()
    secret = "ВНУТРЕННИЙ СЕКРЕТ в памяти"
    (home / "CLAUDE.md").write_text(secret)
    entries = m.scan_memory(home, tmp_path / "empty", platform="linux")
    for e in entries:
        assert secret not in e.content_hash
        assert secret not in e.path
        # у MemoryEntry вообще нет поля с содержимым
        assert not hasattr(e, "content") or getattr(e, "content", None) is None


def test_import_is_followed_relative_to_parent(tmp_path: Path):
    proj = tmp_path / "proj"
    (proj / "docs").mkdir(parents=True)
    # Ссылка относительная — резолвится относительно каталога CLAUDE.md,
    # а не рабочего каталога.
    (proj / "CLAUDE.md").write_text("see @docs/rules.md for details")
    (proj / "docs" / "rules.md").write_text("the hidden instruction")

    entries = m.scan_memory(tmp_path / "home", proj, platform="linux")
    imports = [e for e in entries if e.scope == "import"]
    assert len(imports) == 1
    assert imports[0].path.endswith("docs/rules.md")
    assert imports[0].imported_by.endswith("CLAUDE.md")


def test_import_chain_is_followed_recursively(tmp_path: Path):
    proj = tmp_path / "proj"
    proj.mkdir()
    (proj / "CLAUDE.md").write_text("@a.md")
    (proj / "a.md").write_text("@b.md")
    (proj / "b.md").write_text("@c.md")
    (proj / "c.md").write_text("end of chain")

    entries = m.scan_memory(tmp_path / "home", proj, platform="linux")
    imported = {Path(e.path).name for e in entries if e.scope == "import"}
    assert {"a.md", "b.md", "c.md"} <= imported


def test_import_depth_is_bounded(tmp_path: Path):
    # Claude Code идёт максимум на 4 перехода — глубже мы не заявляем покрытие,
    # чем оно есть. 6-е звено видно быть не должно.
    proj = tmp_path / "proj"
    proj.mkdir()
    (proj / "CLAUDE.md").write_text("@d1.md")
    for i in range(1, 7):
        (proj / f"d{i}.md").write_text(f"@d{i + 1}.md")
    entries = m.scan_memory(tmp_path / "home", proj, platform="linux")
    names = {Path(e.path).name for e in entries if e.scope == "import"}
    assert "d1.md" in names
    assert "d6.md" not in names, "глубина импорта должна быть ограничена"


def test_import_cycle_does_not_hang(tmp_path: Path):
    proj = tmp_path / "proj"
    proj.mkdir()
    (proj / "CLAUDE.md").write_text("@a.md")
    (proj / "a.md").write_text("@b.md")
    (proj / "b.md").write_text("@a.md")  # цикл
    entries = m.scan_memory(tmp_path / "home", proj, platform="linux")
    # Достаточно того, что вызов завершился и каждый файл учтён один раз.
    imported = [e for e in entries if e.scope == "import"]
    paths = [e.path for e in imported]
    assert len(paths) == len(set(paths)), "файл в цикле не должен дублироваться"


def test_at_reference_in_code_block_is_not_an_import(tmp_path: Path):
    proj = tmp_path / "proj"
    proj.mkdir()
    (proj / "real.md").write_text("real")
    # @fake.md — внутри примера кода, это не импорт; @real.md — настоящий.
    (proj / "CLAUDE.md").write_text(
        "run `@fake.md` in shell\n\n```\n@also-fake.md\n```\n\n@real.md\n"
    )
    (proj / "fake.md").write_text("should not be scanned")
    (proj / "also-fake.md").write_text("should not be scanned")

    entries = m.scan_memory(tmp_path / "home", proj, platform="linux")
    imported = {Path(e.path).name for e in entries if e.scope == "import"}
    assert "real.md" in imported
    assert "fake.md" not in imported
    assert "also-fake.md" not in imported


def test_external_import_is_captured_with_provenance(tmp_path: Path):
    # Импорт из home — вне проекта. Это способ спрятать инструкцию вне того, что
    # ревьюят в репозитории; поймать его и есть смысл.
    home = tmp_path / "home"
    home.mkdir()
    (home / "personal.md").write_text("external rule")
    proj = tmp_path / "proj"
    proj.mkdir()
    (proj / "CLAUDE.md").write_text(f"@{home}/personal.md")

    entries = m.scan_memory(tmp_path / "hc", proj, platform="linux")
    ext = [e for e in entries if Path(e.path).name == "personal.md"]
    assert len(ext) == 1
    assert ext[0].scope == "import"
    assert ext[0].imported_by.endswith("CLAUDE.md")


def test_nested_project_claude_md_is_subdir_scope(tmp_path: Path):
    proj = tmp_path / "proj"
    (proj / "sub").mkdir(parents=True)
    (proj / "CLAUDE.md").write_text("root")
    (proj / "sub" / "CLAUDE.md").write_text("nested")
    entries = m.scan_memory(tmp_path / "home", proj, platform="linux")
    subdir = [e for e in entries if e.scope == "subdir"]
    assert any(Path(e.path).name == "CLAUDE.md" for e in subdir)


def test_dependency_dirs_are_skipped(tmp_path: Path):
    # CLAUDE.md внутри node_modules — не память проекта, а чужой пакет; Claude
    # Code её так не грузит, и обход туда стоил бы дорого.
    proj = tmp_path / "proj"
    (proj / "node_modules" / "pkg").mkdir(parents=True)
    (proj / "node_modules" / "pkg" / "CLAUDE.md").write_text("vendor")
    entries = m.scan_memory(tmp_path / "home", proj, platform="linux")
    assert not any("node_modules" in e.path for e in entries)


def test_missing_files_are_silent(tmp_path: Path):
    # Ничего нет — пустой список, а не падение.
    entries = m.scan_memory(tmp_path / "home", tmp_path / "proj", platform="linux")
    assert entries == []


# --- прочие носители инструкций ---------------------------------------------


def test_project_and_user_rules_are_scanned(tmp_path: Path):
    home = tmp_path / "home"
    (home / "rules").mkdir(parents=True)
    (home / "rules" / "global.md").write_text("user rule")
    proj = tmp_path / "proj"
    (proj / ".claude" / "rules" / "sub").mkdir(parents=True)
    (proj / ".claude" / "rules" / "testing.md").write_text("test rule")
    (proj / ".claude" / "rules" / "sub" / "nested.md").write_text("nested rule")

    entries = m.scan_memory(home, proj, platform="linux")
    rules = {Path(e.path).name for e in entries if e.scope == "rules"}
    assert {"global.md", "testing.md", "nested.md"} <= rules


def test_output_styles_are_scanned(tmp_path: Path):
    home = tmp_path / "home"
    (home / "output-styles").mkdir(parents=True)
    (home / "output-styles" / "teaching.md").write_text("append to system prompt")
    proj = tmp_path / "proj"
    (proj / ".claude" / "output-styles").mkdir(parents=True)
    (proj / ".claude" / "output-styles" / "terse.md").write_text("be terse")

    entries = m.scan_memory(home, proj, platform="linux")
    styles = {Path(e.path).name for e in entries if e.scope == "output_style"}
    assert {"teaching.md", "terse.md"} <= styles


def test_managed_claude_md_key_is_hashed(tmp_path: Path):
    # claudeMd внутри managed-settings.json — прямой текст политики организации.
    managed_dir = tmp_path / "mc"
    managed_dir.mkdir()
    settings = managed_dir / "managed-settings.json"
    settings.write_text('{"claudeMd": "Always run make lint before commit."}')

    # Подменяем путь managed-settings на наш временный.
    orig = dict(m._MANAGED_SETTINGS_PATHS)
    m._MANAGED_SETTINGS_PATHS["linux"] = str(settings)
    try:
        entries = m.scan_memory(tmp_path / "home", tmp_path / "proj", platform="linux")
    finally:
        m._MANAGED_SETTINGS_PATHS.clear()
        m._MANAGED_SETTINGS_PATHS.update(orig)

    managed = [e for e in entries if e.scope == "managed_memory"]
    assert len(managed) == 1
    assert managed[0].path.endswith("#claudeMd")
    # Хешируется значение ключа, не весь файл.
    import hashlib
    expected = hashlib.sha256(b"Always run make lint before commit.").hexdigest()
    assert managed[0].content_hash == expected


def test_managed_settings_without_claude_md_key_is_silent(tmp_path: Path):
    managed_dir = tmp_path / "mc"
    managed_dir.mkdir()
    settings = managed_dir / "managed-settings.json"
    settings.write_text('{"permissions": {"deny": []}}')  # нет claudeMd
    orig = dict(m._MANAGED_SETTINGS_PATHS)
    m._MANAGED_SETTINGS_PATHS["linux"] = str(settings)
    try:
        entries = m.scan_memory(tmp_path / "home", tmp_path / "proj", platform="linux")
    finally:
        m._MANAGED_SETTINGS_PATHS.clear()
        m._MANAGED_SETTINGS_PATHS.update(orig)
    assert not any(e.scope == "managed_memory" for e in entries)


def test_rules_do_not_pull_at_imports(tmp_path: Path):
    # @import — механизм CLAUDE.md, не правил. Из правила его тянуть не должны,
    # иначе выдумаем покрытие, которого у Claude Code нет.
    proj = tmp_path / "proj"
    (proj / ".claude" / "rules").mkdir(parents=True)
    (proj / ".claude" / "rules" / "r.md").write_text("@secret.md")
    (proj / "secret.md").write_text("should not be pulled from a rule")
    entries = m.scan_memory(tmp_path / "home", proj, platform="linux")
    assert not any(Path(e.path).name == "secret.md" for e in entries)
