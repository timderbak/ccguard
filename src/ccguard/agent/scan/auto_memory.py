"""Сканер АВТО-памяти Claude Code (ASI06 — отравление памяти/контекста).

Авто-память — это память, которую агент ведёт и переписывает САМ между сессиями
(файл ``MEMORY.md`` как индекс + тематические файлы), в отличие от CLAUDE.md,
который пишет человек. Она включена по умолчанию и лежит машинно-локально в
``~/.claude/projects/<project>/memory/`` (путь можно переопределить настройкой
``autoMemoryDirectory``). Индексный ``MEMORY.md`` подгружается в КАЖДУЮ сессию.

Угроза: отравленный текст, попавший в авто-память, персистит и влияет на будущие
сессии с полномочиями самого агента — для него это его собственная память, а не
входные данные, которые он обязан перепроверять.

Ключевое отличие от сканера CLAUDE.md: content_hash тут почти бесполезен —
авто-память меняется каждую сессию легитимно (агент дописывает выученное).
Поэтому мы считаем числовые ПРИЗНАКИ (features), а сервер ловит аномальную дельту
между снимками. По конституции проекта содержимое НЕ передаётся — только счётчики
и отпечаток; всё считается здесь, на стороне агента.

Пути мы не выводим из ключа проекта (Claude Code кодирует его через дефисы и это
хрупко) — вместо этого честно обходим все ``projects/*/memory/`` на машине: каждая
авто-память — поверхность отравления, и пропустить её из-за неверно угаданного
ключа было бы хуже, чем показать чуть больше.
"""
from __future__ import annotations

import hashlib
import re
from pathlib import Path

from ccguard.agent.scan.settings import ParsedSettings
from ccguard.schemas import AutoMemoryStats

# Память в мегабайты не бывает нормальной; признаки считаем по первому мегабайту,
# но размер помечаем честно — раздутый файл сам по себе повод посмотреть.
_MAX_FILE_BYTES = 1_048_576  # 1 МБ
# Разумный потолок числа файлов, чтобы патологический случай (сотни проектов) не
# раздул отчёт. Если превышен — просто берём первые; это инвентарь, не форензика.
_MAX_FILES = 500

# @import: @ + путь до пробела/бэктика (как в CLAUDE.md).
_IMPORT_RE = re.compile(r"(?<![`\w])@([^\s`]+)")
_URL_RE = re.compile(r"https?://", re.IGNORECASE)

# Узкий набор ВЫСОКОСИГНАЛЬНЫХ атака-маркеров. Это не «инструкции вообще»
# (языкозависимо и шумно), а технические маркеры, которых в заметках-о-коде почти
# не бывает, но которые типичны для закладки в память. Сервер ловит их СКАЧОК
# между снимками, а не само присутствие, — так одиночное легитимное упоминание
# («тестируй API через curl») не поднимает тревогу.
_SUSPICIOUS_MARKERS: tuple[re.Pattern, ...] = tuple(
    re.compile(p, re.IGNORECASE)
    for p in (
        r"ignore\s+(all\s+)?previous",
        r"disregard\s+(all\s+)?(previous|prior|above)",
        r"system\s+prompt",
        r"\bcurl\b",
        r"\bwget\b",
        r"base64\s+(-d|--decode)",
        r"\|\s*(sh|bash|zsh)\b",
        r"/etc/(shadow|passwd)",
        r"\bid_rsa\b",
        r"\.ssh/",
        r"AWS_SECRET|AWS_ACCESS_KEY",
        r"\bapi[_-]?key\b",
        r"-----BEGIN [A-Z ]*PRIVATE KEY-----",
    )
)


def _strip_code(text: str) -> str:
    """Убрать fenced и inline код: @-ссылки внутри них — текст, не импорт."""
    text = re.sub(r"```.*?```", " ", text, flags=re.DOTALL)
    text = re.sub(r"~~~.*?~~~", " ", text, flags=re.DOTALL)
    text = re.sub(r"`[^`]*`", " ", text)
    return text


def extract_stats(text: str, path: str) -> AutoMemoryStats:
    """Посчитать признаки авто-памяти по её тексту. Чистая функция (без ФС).

    Все числа языко-агностичны и дёшевы: размер, строки, @import (всего и наружу),
    URL, атака-маркеры, отпечаток. ``external`` определяем по форме ссылки
    (начинается с ``~`` или абсолютного пути) — это не требует файловой системы и
    надёжно: авто-память, тянущая файл извне проекта, — аномалия сама по себе.
    """
    size_bytes = len(text.encode("utf-8"))
    line_count = text.count("\n") + 1 if text else 0

    stripped = _strip_code(text)
    imports = _IMPORT_RE.findall(stripped)
    import_count = len(imports)
    external_import_count = sum(
        1 for raw in imports if raw.startswith("~") or raw.startswith("/")
    )

    url_count = len(_URL_RE.findall(text))
    suspicious = sum(len(rx.findall(text)) for rx in _SUSPICIOUS_MARKERS)
    content_hash = hashlib.sha256(text.encode("utf-8")).hexdigest()

    return AutoMemoryStats(
        path=path,
        size_bytes=size_bytes,
        line_count=line_count,
        import_count=import_count,
        external_import_count=external_import_count,
        url_count=url_count,
        suspicious_marker_count=suspicious,
        content_hash=content_hash,
    )


def _memory_dirs(claude_home: Path, parsed: list[ParsedSettings]) -> list[Path]:
    """Каталоги авто-памяти: все projects/*/memory/ + override autoMemoryDirectory."""
    dirs: list[Path] = []
    seen: set[str] = set()

    def _add(d: Path) -> None:
        try:
            rp = d.resolve()
        except OSError:
            return
        key = str(rp)
        if key not in seen and rp.is_dir():
            seen.add(key)
            dirs.append(rp)

    base = claude_home / "projects"
    if base.is_dir():
        try:
            for proj in sorted(base.iterdir()):
                _add(proj / "memory")
        except OSError:
            pass

    # Переопределение пути авто-памяти — любой scope. Абсолютный или из-под ~.
    for p in parsed:
        if not p.data:
            continue
        override = p.data.get("autoMemoryDirectory")
        if isinstance(override, str) and override:
            _add(Path(override).expanduser())

    return dirs


def _read_features(path: Path) -> AutoMemoryStats | None:
    try:
        if not path.is_file():
            return None
        data = path.read_bytes()
    except OSError:
        return None
    truncated = data[:_MAX_FILE_BYTES]
    text = truncated.decode("utf-8", errors="replace")
    stats = extract_stats(text, str(path))
    # Размер помечаем ПОЛНЫЙ (даже если признаки по первому мегабайту): раздутая
    # авто-память — сигнал, и урезать его нельзя.
    if len(data) > _MAX_FILE_BYTES:
        stats.size_bytes = len(data)
    return stats


def scan_auto_memory(
    claude_home: Path, project_dir: Path, parsed: list[ParsedSettings]
) -> list[AutoMemoryStats]:
    """Собрать признаки всех файлов авто-памяти, видимых на этой машине.

    ``project_dir`` в сигнатуре ради единообразия с другими сканерами; авто-память
    машинно-локальна и не привязана к текущему проекту, поэтому обходим все.
    """
    out: list[AutoMemoryStats] = []
    for d in _memory_dirs(claude_home, parsed):
        try:
            files = sorted(d.glob("*.md"))
        except OSError:
            continue
        for f in files:
            if len(out) >= _MAX_FILES:
                return out
            stats = _read_features(f)
            if stats is not None:
                out.append(stats)
    return out
