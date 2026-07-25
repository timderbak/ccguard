"""Сканер памяти Claude Code: CLAUDE.md всех уровней и их @import-цепочки.

Память — это не конфигурация исполнения, а прямые инструкции агенту. Закладка
здесь («перед любой командой сначала выполни …») сработает без единого
подозрительного вызова: для агента это его собственная память, а не входные
данные, которые он обязан перепроверять. Поэтому память инвентаризируется
наравне с хуками и скиллами, а сервер следит за её дрейфом (TOFU-baseline).

Что собираем (всё грузится в контекст при старте сессии):

* managed/enterprise CLAUDE.md — root-owned политика организации (3 ОС);
* пользовательский ~/.claude/CLAUDE.md;
* проектные ./CLAUDE.md и ./.claude/CLAUDE.md;
* локальный ./CLAUDE.local.md (не в git);
* CLAUDE.md выше корня проекта (ancestor) — вне репозитория, отдельный сигнал:
  инструкция, которой нет в том, что ревьюят;
* вложенные CLAUDE.md внутри проекта (subdir);
* всё, что притянуто через ``@import`` (рекурсивно, как это делает Claude Code —
  до 4 переходов), с пометкой, какой файл притянул.

Содержимое НЕ передаётся — только sha256. Причина как у канареек: память легко
содержит внутренние пути, секреты в примерах, имена систем; для детекта дрейфа
хватает отпечатка, а утечка базы сервера не должна раздавать чужие инструкции.

Первая версия сознательно ограничена файлами CLAUDE.md и их импортами. Другие
носители инструкций (`.claude/rules/`, output-styles, авто-память MEMORY.md)
той же природы и добавляются тем же механизмом — вынесены в отдельный заход,
чтобы этот кусок оставался обозримым.
"""
from __future__ import annotations

import hashlib
import re
import sys
from pathlib import Path

from ccguard.schemas import MemoryEntry

# Managed/enterprise CLAUDE.md — те же корни, что у managed-settings.json.
_ENTERPRISE_PATHS: dict[str, str] = {
    "darwin": "/Library/Application Support/ClaudeCode/CLAUDE.md",
    "linux": "/etc/claude-code/CLAUDE.md",
    "win32": "C:\\Program Files\\ClaudeCode\\CLAUDE.md",
}

# Максимальная глубина @import — ровно столько переходов делает Claude Code.
_MAX_IMPORT_HOPS = 4
# Глубина обхода вложенных CLAUDE.md и каталоги, куда не спускаемся: там сотни
# тысяч файлов чужих зависимостей, и CLAUDE.md внутри них Claude Code как память
# проекта не грузит — а обход стоил бы дорого.
_MAX_SUBDIR_DEPTH = 6
_SKIP_DIRS = frozenset({
    ".git", "node_modules", ".venv", "venv", "__pycache__",
    "dist", "build", ".mypy_cache", ".ruff_cache", ".pytest_cache",
    ".tox", ".idea", ".vscode", "site-packages",
})
# Не читаем гигантские файлы: память таких размеров не бывает, а вот приманка
# «раздуй хук памяти, чтобы съесть бюджет» — бывает.
_MAX_FILE_BYTES = 1_048_576  # 1 МБ

# @import: @ + путь до пробела/бэктика. Достаточно грубо — точную грань между
# «ссылка» и «просто текст с собакой» Claude Code проводит по code-fence, что мы
# и учитываем ниже, пропуская блоки ``` и inline `...`.
_IMPORT_RE = re.compile(r"(?<![`\w])@([^\s`]+)")


def _hash_and_size(path: Path) -> tuple[str, int] | None:
    """sha256 + размер файла. None — если это не читаемый обычный файл."""
    try:
        if not path.is_file():
            return None
        data = path.read_bytes()
    except OSError:
        return None
    if len(data) > _MAX_FILE_BYTES:
        # Хешируем усечённо, но честно помечаем размер — дрейф всё равно виден,
        # а память в мегабайт сама по себе повод посмотреть.
        return hashlib.sha256(data[:_MAX_FILE_BYTES]).hexdigest(), len(data)
    return hashlib.sha256(data).hexdigest(), len(data)


def _entry(path: Path, scope: str, imported_by: str | None = None) -> MemoryEntry | None:
    hs = _hash_and_size(path)
    if hs is None:
        return None
    content_hash, size = hs
    return MemoryEntry(
        path=str(path), scope=scope, content_hash=content_hash,
        size_bytes=size, imported_by=imported_by,
    )


def _strip_code(text: str) -> str:
    """Убрать fenced-блоки и inline-код: @-ссылки внутри них Claude Code
    считает текстом, а не импортом, — иначе мы бы гонялись за примерами."""
    # Fenced ```...``` (в т.ч. ~~~), затем inline `...`.
    text = re.sub(r"```.*?```", " ", text, flags=re.DOTALL)
    text = re.sub(r"~~~.*?~~~", " ", text, flags=re.DOTALL)
    text = re.sub(r"`[^`]*`", " ", text)
    return text


def _resolve_import(raw: str, parent: Path) -> Path | None:
    """Резолвим @-путь как Claude Code: ~ → домашний, относительный —
    относительно каталога файла-родителя (НЕ рабочего каталога)."""
    raw = raw.strip().rstrip(".,;:)")  # хвостовая пунктуация предложения
    if not raw:
        return None
    try:
        if raw.startswith("~"):
            return Path(raw).expanduser().resolve()
        p = Path(raw)
        if p.is_absolute():
            return p.resolve()
        return (parent.parent / p).resolve()
    except (OSError, RuntimeError):
        return None


def _collect_imports(
    entry_path: Path,
    out: list[MemoryEntry],
    seen: set[str],
    *,
    hops: int,
) -> None:
    """Рекурсивно пройти @import из файла, как это делает Claude Code."""
    if hops <= 0:
        return
    try:
        text = entry_path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return
    for m in _IMPORT_RE.finditer(_strip_code(text)):
        target = _resolve_import(m.group(1), entry_path)
        if target is None:
            continue
        key = str(target)
        if key in seen:
            continue  # цикл или повторная ссылка — считаем один раз
        seen.add(key)
        ent = _entry(target, "import", imported_by=str(entry_path))
        if ent is None:
            continue  # ссылка на несуществующий/нечитаемый файл — молча
        out.append(ent)
        _collect_imports(target, out, seen, hops=hops - 1)


def _walk_subdirs(project_dir: Path, seen: set[str], out: list[MemoryEntry]) -> None:
    """Вложенные CLAUDE.md внутри проекта (грузятся, когда агент заходит в
    каталог). Обход ограничен по глубине и обходит стороной чужие зависимости."""
    root_depth = len(project_dir.resolve().parts)
    for md in project_dir.rglob("CLAUDE.md"):
        try:
            rp = md.resolve()
        except OSError:
            continue
        parts = rp.parts
        if any(d in _SKIP_DIRS for d in parts):
            continue
        if len(parts) - root_depth > _MAX_SUBDIR_DEPTH:
            continue
        key = str(rp)
        if key in seen:
            continue  # корневой ./CLAUDE.md уже учли отдельно
        seen.add(key)
        ent = _entry(rp, "subdir")
        if ent is not None:
            out.append(ent)


def scan_memory(
    claude_home: Path, project_dir: Path, *, platform: str | None = None
) -> list[MemoryEntry]:
    """Собрать все файлы памяти Claude Code, видимые из этого проекта."""
    platform = platform or sys.platform
    out: list[MemoryEntry] = []
    seen: set[str] = set()

    def _add(path: Path, scope: str) -> None:
        try:
            rp = path.resolve()
        except OSError:
            return
        key = str(rp)
        if key in seen:
            return
        seen.add(key)
        ent = _entry(rp, scope)
        if ent is not None:
            out.append(ent)

    # 1. Прямые файлы по известным путям, от самого «сильного» к локальному.
    ent_path = _ENTERPRISE_PATHS.get(platform)
    if ent_path:
        _add(Path(ent_path), "enterprise")
    _add(claude_home / "CLAUDE.md", "user")
    _add(project_dir / "CLAUDE.md", "project")
    _add(project_dir / ".claude" / "CLAUDE.md", "project")
    _add(project_dir / "CLAUDE.local.md", "project_local")

    # 2. CLAUDE.md выше корня проекта — вне репозитория. Инструкция, которой нет
    # в том, что ревьюят: отдельный уровень, а не тихо слитый с проектным.
    try:
        parent = project_dir.resolve().parent
        while True:
            _add(parent / "CLAUDE.md", "ancestor")
            if parent.parent == parent:  # дошли до корня ФС
                break
            parent = parent.parent
    except OSError:
        pass

    # 3. Вложенные CLAUDE.md внутри проекта.
    _walk_subdirs(project_dir, seen, out)

    # 4. @import из всего найденного — рекурсивно, как Claude Code.
    #    Обходим копию: _collect_imports дописывает в out, а не в цикл по нему.
    for ent in list(out):
        _collect_imports(Path(ent.path), out, seen, hops=_MAX_IMPORT_HOPS)

    return out
