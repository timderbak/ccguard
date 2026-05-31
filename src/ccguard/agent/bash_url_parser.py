"""Extract URLs / network targets from bash command strings.

Используется в `_decide_bash` чтобы перед dangerous-patterns/denylist
проверить URL'ы в curl/wget/http/nc по тому же каталогу подозрительных
хостов, что и для WebFetch.

Не пытается понять семантику bash до конца (это невозможно в общем случае:
команда вида ``URL=https://...; curl "$URL"`` не разрешится без env).
Цель — поймать прямые литералы URL в типичных сетевых инструментах.
"""
from __future__ import annotations

import re
import shlex

_NETWORK_TOOLS = {"curl", "wget", "http", "https", "httpie", "nc", "netcat"}

# URL-литерал: http(s) или явная схема. Допускаем кавычки вокруг (shlex
# их снимает).
_URL_LITERAL = re.compile(r"^https?://\S+$", re.IGNORECASE)

# Хост:порт без схемы (для `nc host port`).
_HOST_TOKEN = re.compile(r"^[a-zA-Z0-9._:\[\]-]+$")


def _looks_like_url(tok: str) -> bool:
    return bool(_URL_LITERAL.match(tok))


def _looks_like_host(tok: str) -> bool:
    # Минимальная эвристика: точка или цифры (IPv4) или `:` (IPv6 in brackets).
    if not _HOST_TOKEN.match(tok):
        return False
    return "." in tok or ":" in tok


def _split_pipes(command: str) -> list[str]:
    """Грубо разбить по pipe/redirect, чтобы каждый сегмент был
    самостоятельной командой. shlex не понимает ``|``, мы делаем
    предварительный сплит.
    """
    # Заменяем ``|``, ``;``, ``&&``, ``||`` на разделитель новой команды.
    # Простая регэксп-замена; не идеально (внутри кавычек поломается),
    # но shlex дальше разберётся.
    parts: list[str] = []
    buf: list[str] = []
    in_single = False
    in_double = False
    i = 0
    while i < len(command):
        ch = command[i]
        if ch == "'" and not in_double:
            in_single = not in_single
            buf.append(ch)
        elif ch == '"' and not in_single:
            in_double = not in_double
            buf.append(ch)
        elif not in_single and not in_double:
            # ``&&``, ``||``
            if ch in "|&;" and i + 1 < len(command) and command[i + 1] == ch:
                parts.append("".join(buf))
                buf = []
                i += 2
                continue
            if ch in "|;":
                parts.append("".join(buf))
                buf = []
                i += 1
                continue
            # ``>``, ``<``, ``>>`` — редиректы, всё после них до пробела не
            # часть аргументов curl; удобнее обрезать сегмент.
            if ch == ">":
                parts.append("".join(buf))
                buf = []
                # пропустить редирект-токен + следующее слово
                while i < len(command) and command[i] != " ":
                    i += 1
                continue
            buf.append(ch)
        else:
            buf.append(ch)
        i += 1
    parts.append("".join(buf))
    return [p.strip() for p in parts if p.strip()]


def _parse_tokens(segment: str) -> list[str]:
    """shlex с fallback на простой split при ошибке (незакрытая кавычка и т.п.)."""
    try:
        return shlex.split(segment, posix=True)
    except ValueError:
        # Не падаем — лучше частичный результат через простой split.
        return segment.split()


def extract_urls_from_command(command: str) -> list[str]:
    """Извлечь URL / host-токены из bash-команды.

    Возвращает список найденных URL/хост-токенов (в порядке появления,
    без дедупликации — у вызывающего может быть своя политика).

    Поведение:

    * Команды, не относящиеся к сетевым инструментам, игнорируются.
    * В сетевой команде первый non-flag токен, похожий на URL/хост,
      добавляется в результат.
    * Поддерживается ``-O``/``-o``/``--url`` со следующим аргументом
      (curl/wget) — URL в этих позициях тоже подхватывается.
    * Никаких exception'ов не бросает: на странном вводе вернёт
      пустой / частичный список.
    """
    if not command or not isinstance(command, str):
        return []
    out: list[str] = []
    for seg in _split_pipes(command):
        tokens = _parse_tokens(seg)
        if not tokens:
            continue
        # имя команды — первый токен, очищенный от пути (basename достаточно).
        cmd_name = tokens[0].rsplit("/", 1)[-1].lower()
        if cmd_name not in _NETWORK_TOOLS:
            continue
        # Проход по аргументам: ищем URL-литералы или следующий за -O/-o/--url.
        i = 1
        while i < len(tokens):
            tok = tokens[i]
            # явные «следующий аргумент — URL» флаги
            if tok in {"-O", "-o", "--url", "--output"} and i + 1 < len(tokens):
                nxt = tokens[i + 1]
                if _looks_like_url(nxt):
                    out.append(nxt)
                # ``-O /tmp/x`` — следующий путь, не URL: пропускаем.
                i += 2
                continue
            # пропускаем флаги (-* / --*) и их значения, если значения
            # явно не URL
            if tok.startswith("-"):
                i += 1
                continue
            if _looks_like_url(tok):
                out.append(tok)
            elif _looks_like_host(tok) and cmd_name in {"nc", "netcat"}:
                # для nc первый non-flag — хост
                out.append(tok)
            i += 1
    return out
