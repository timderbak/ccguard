"""Сканер файлов-инструкций Cursor (agent_kind=cursor, ASI06).

Cursor — второй AI-редактор на фундаменте agent_kind. Его «память»/инструкции —
это НЕ авто-память (та у Cursor облачная), а файлы правил в репозитории, той же
природы, что CLAUDE.md у Claude Code: текст, который агент грузит в контекст и
исполняет как свои инструкции. Поэтому едут через тот же ``MemoryEntry`` и тот
же ``memory_baseline_service`` — дрейф инструкций Cursor детектируется даром.

Что собираем (высокая уверенность по докам/сообществу):

* ``.cursor/rules/**/*.mdc`` — правила Cursor (MDC: YAML-frontmatter + Markdown),
  включая вложенные ``.cursor/rules/`` в подкаталогах;
* ``.cursor/rules/**/RULE.md`` — документированный папочный формат (сканируем
  оба, т.к. какой «канонический» — на практике неоднозначно);
* legacy ``.cursorrules`` в корне проекта (устаревший, но поддерживается);
* ``AGENTS.md`` (корень и вложенные) — кросс-инструментальный файл инструкций.

По конституции проекта содержимое НЕ передаётся — только sha256 и размер.
Frontmatter в v1 НЕ парсим (хешируем файл целиком) — этого хватает для дрейфа.
"""
from __future__ import annotations

import hashlib
from pathlib import Path

from ccguard.schemas import MemoryEntry

# Каталоги чужих зависимостей: правил Cursor там не бывает, а обход дорог.
_SKIP_DIRS = frozenset({
    ".git", "node_modules", ".venv", "venv", "__pycache__",
    "dist", "build", ".mypy_cache", ".ruff_cache", ".pytest_cache",
    ".tox", ".idea", ".vscode", "site-packages",
})
_MAX_FILE_BYTES = 1_048_576  # 1 МБ — та же логика, что в scan/memory.py
_MAX_DEPTH = 8  # глубина обхода AGENTS.md/вложенных .cursor относительно корня


def _hash_and_size(path: Path) -> tuple[str, int] | None:
    try:
        if not path.is_file():
            return None
        data = path.read_bytes()
    except OSError:
        return None
    if len(data) > _MAX_FILE_BYTES:
        return hashlib.sha256(data[:_MAX_FILE_BYTES]).hexdigest(), len(data)
    return hashlib.sha256(data).hexdigest(), len(data)


def _skipped(path: Path) -> bool:
    return any(part in _SKIP_DIRS for part in path.parts)


def scan_cursor_rules(project_dir: Path) -> list[MemoryEntry]:
    """Собрать файлы-инструкции Cursor, видимые из этого проекта."""
    out: list[MemoryEntry] = []
    seen: set[str] = set()
    try:
        root_depth = len(project_dir.resolve().parts)
    except OSError:
        return out

    def _add(path: Path, scope: str) -> None:
        try:
            rp = path.resolve()
        except OSError:
            return
        if _skipped(rp):
            return
        if len(rp.parts) - root_depth > _MAX_DEPTH:
            return
        key = str(rp)
        if key in seen:
            return
        seen.add(key)
        hs = _hash_and_size(rp)
        if hs is None:
            return
        content_hash, size = hs
        out.append(MemoryEntry(
            path=str(rp), scope=scope, content_hash=content_hash, size_bytes=size,
        ))

    # 1. Правила Cursor: все .cursor/rules/ на любой глубине (вложенные правила).
    try:
        cursor_dirs = list(project_dir.rglob(".cursor"))
    except OSError:
        cursor_dirs = []
    for cdir in cursor_dirs:
        if _skipped(cdir):
            continue
        rules_dir = cdir / "rules"
        if not rules_dir.is_dir():
            continue
        try:
            candidates = list(rules_dir.rglob("*.mdc")) + list(rules_dir.rglob("RULE.md"))
        except OSError:
            continue
        for f in sorted(candidates):
            _add(f, "cursor_rules")

    # 2. Legacy .cursorrules — один файл в корне проекта.
    _add(project_dir / ".cursorrules", "cursor_legacy")

    # 3. AGENTS.md — корень и вложенные каталоги.
    try:
        agents_files = list(project_dir.rglob("AGENTS.md"))
    except OSError:
        agents_files = []
    for f in sorted(agents_files):
        _add(f, "agents_md")

    return out
