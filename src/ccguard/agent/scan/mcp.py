"""Извлечение MCP-серверов из settings.json и .mcp.json."""

from __future__ import annotations

import contextlib
import hashlib
import json
from pathlib import Path
from typing import Any

from ccguard.agent.masking import mask_secrets
from ccguard.agent.scan.settings import ParsedSettings
from ccguard.schemas import McpServerEntry


def _hash_text(text: str | None) -> str | None:
    """sha256 hexdigest truncated to 16 chars, or None for empty/None input.

    Used as the baseline material for MCP rug pull detection — short hashes
    are enough for collision-resistance at our scale (<<1M MCP entries).
    """
    if not text:
        return None
    return hashlib.sha256(text.encode("utf-8")).hexdigest()[:16]


def tools_hash(tools: object) -> str | None:
    """Order-independent hash of a runtime tool list (name+description+schema).

    The rug-pull surface lives here (tool descriptions AND the ``inputSchema`` —
    the JSON parameter schema — are fed to the LLM as authoritative instructions,
    so line-jumping injection can hide in schema field descriptions too). Returns
    None when no usable tool list exists, so the baseline diff is simply skipped
    (back-compat with no-tools agents).

    ``inputSchema`` is folded in ONLY when a tool actually carries one, so a
    schema-less tool hashes exactly as before — an agent upgrade does not spuriously
    fire ``tools_changed`` for the common stdio/config case that has no schema.
    """
    if not isinstance(tools, list) or not tools:
        return None
    parts: list[str] = []
    for t in tools:
        if not isinstance(t, dict):
            continue
        name = str(t.get("name", ""))
        desc = str(t.get("description", ""))
        part = f"{name}\x1f{desc}"
        # MCP spec uses camelCase ``inputSchema``; tolerate snake_case too.
        schema = t.get("inputSchema")
        if schema is None:
            schema = t.get("input_schema")
        if schema is not None:
            # unserializable schema → hash on name+desc only (no crash)
            with contextlib.suppress(TypeError, ValueError):
                part += "\x1f" + json.dumps(schema, sort_keys=True, ensure_ascii=False)
        parts.append(part)
    if not parts:
        return None
    return _hash_text("\x1e".join(sorted(parts)))


def _definition_text(command: str | None, args: list[str], url: str | None) -> str:
    """Канонический "контракт" MCP-сервера для definition_hash.

    Format: ``"{command} {arg1 arg2 ...} | {url}"``. Stable, language-free,
    independent of dict-ordering.
    """
    cmd = command or ""
    args_str = " ".join(args)
    url_s = url or ""
    return f"{cmd} {args_str} | {url_s}"


def _classify_transport(spec: dict[str, Any]) -> str:
    """По форме спецификации определить transport: stdio/http/sse."""
    if "url" in spec:
        # У http/sse различия в полях, но в settings.json часто общий 'url'
        ttype = (spec.get("type") or "").lower()
        if ttype == "sse":
            return "sse"
        return "http"
    return "stdio"


def _entry_from_spec(
    name: str,
    spec: dict[str, Any],
    source: str,
    *,
    scope: str | None = None,
    origin: str = "local",
    parent_plugin: str | None = None,
    source_marketplace: str | None = None,
) -> McpServerEntry | None:
    if not isinstance(spec, dict):
        return None
    transport = _classify_transport(spec)
    env = spec.get("env") or {}
    env_keys = list(env.keys()) if isinstance(env, dict) else []
    args_val = spec.get("args") or []
    raw_args = [str(a) for a in args_val] if isinstance(args_val, list) else []
    # Маскируем секреты (JWT, PAT, и т.п.) в args, command, url до сохранения.
    args = [mask_secrets(a) or "" for a in raw_args]
    raw_cmd = spec.get("command")
    command = mask_secrets(raw_cmd) if isinstance(raw_cmd, str) else raw_cmd
    raw_url = spec.get("url")
    url = mask_secrets(raw_url) if isinstance(raw_url, str) else raw_url
    # MCP rug pull detection: capture description (if present in config) +
    # compute baseline hashes. Description may live in the MCP spec itself
    # (some plugins write it into ~/.claude.json); otherwise stays None.
    raw_desc = spec.get("description")
    description = raw_desc if isinstance(raw_desc, str) else None
    description_hash = _hash_text(description)
    definition_hash = _hash_text(_definition_text(command, args, url))
    # P4b: capture runtime tool descriptions if the config embeds a resolved
    # `tools` array; else, when the operator opted in (CCGUARD_MCP_PROBE), probe
    # the http/sse server's tools/list over HTTP (no process spawn; fail-safe).
    tools_h = tools_hash(spec.get("tools"))
    if tools_h is None and transport in ("http", "sse"):
        from ccguard.agent import mcp_probe  # lazy: avoid import cycle

        if mcp_probe.is_enabled():
            raw_headers = spec.get("headers") if isinstance(spec.get("headers"), dict) else None
            tools_h = mcp_probe.probe_tools_hash(raw_url, raw_headers)
    return McpServerEntry(
        name=name,
        transport=transport,  # type: ignore[arg-type]
        command=command,
        args=args,
        url=url,
        env_keys=env_keys,
        source=source,
        description=description,
        description_hash=description_hash,
        definition_hash=definition_hash,
        tools_hash=tools_h,
        scope=scope,  # type: ignore[arg-type]
        origin=origin,  # type: ignore[arg-type]
        parent_plugin=parent_plugin,
        source_marketplace=source_marketplace,
    )


def extract_from_settings(parsed_list: list[ParsedSettings]) -> list[McpServerEntry]:
    """Извлечь MCP-серверы из набора settings.json (поле mcpServers)."""
    out: list[McpServerEntry] = []
    seen: set[tuple[str, str]] = set()  # (name, source)
    for p in parsed_list:
        if p.data is None:
            continue
        servers = p.data.get("mcpServers") or {}
        if not isinstance(servers, dict):
            continue
        for name, spec in servers.items():
            # p.source.scope уже вычислен парсером settings (user/project/
            # project_local/managed) — это и есть ответ на «кто это поставил».
            entry = _entry_from_spec(name, spec, p.source.path, scope=p.source.scope)
            if entry is not None and (entry.name, entry.source) not in seen:
                out.append(entry)
                seen.add((entry.name, entry.source))
    return out


def _extract_from_mcp_json_file(
    path: Path,
    source_label: str | None = None,
    *,
    scope: str | None = None,
    origin: str = "local",
    parent_plugin: str | None = None,
    source_marketplace: str | None = None,
) -> list[McpServerEntry]:
    """Разобрать произвольный JSON-файл вида {"mcpServers": {...}}."""
    if not path.exists():
        return []
    try:
        data = json.loads(path.read_text())
    except (json.JSONDecodeError, OSError):
        return []
    if not isinstance(data, dict):
        return []
    servers = data.get("mcpServers") or {}
    if not isinstance(servers, dict):
        return []
    src = source_label or str(path)
    out: list[McpServerEntry] = []
    for name, spec in servers.items():
        entry = _entry_from_spec(
            name, spec, src,
            scope=scope, origin=origin,
            parent_plugin=parent_plugin, source_marketplace=source_marketplace,
        )
        if entry:
            out.append(entry)
    return out


def extract_from_mcp_json(project_dir: Path) -> list[McpServerEntry]:
    """`.mcp.json` в корне проекта — альтернативный формат.

    scope=project: файл лежит в репозитории и приезжает к каждому, кто клонирует
    проект — то есть решение командное, а не персональное.
    """
    return _extract_from_mcp_json_file(project_dir / ".mcp.json", scope="project")


def extract_from_user_mcp_json(claude_home: Path) -> list[McpServerEntry]:
    """Per-user `~/.claude/.mcp.json` — глобальный MCP-конфиг.

    scope=user: персональный файл разработчика — «поставил себе сам».
    """
    return _extract_from_mcp_json_file(claude_home / ".mcp.json", scope="user")


def extract_from_cursor_mcp_json(
    project_dir: Path, cursor_home: Path
) -> list[McpServerEntry]:
    """MCP-серверы Cursor: ``.cursor/mcp.json`` (проект) + ``~/.cursor/mcp.json`` (user).

    Формат идентичен ``.mcp.json`` Claude Code (``{"mcpServers": {...}}``), поэтому
    разбираем тем же ``_extract_from_mcp_json_file``: ``_classify_transport`` даёт
    url→http для remote-серверов даже без поля ``type`` (у Cursor оно
    необязательно), маскирование секретов и хеши работают как есть.

    Оба файла сканируем НЕЗАВИСИМО (каждый — свой ``McpServerEntry`` со своим
    scope), сознательно обходя нестабильную между версиями merge/precedence-
    семантику Cursor: рассуждать об «эффективном конфиге» здесь нельзя.
    """
    out = _extract_from_mcp_json_file(project_dir / ".cursor" / "mcp.json", scope="project")
    out.extend(_extract_from_mcp_json_file(cursor_home / "mcp.json", scope="user"))
    return out


def extract_from_claude_json(claude_json_path: Path) -> list[McpServerEntry]:
    """`~/.claude.json` — основной конфиг Claude Code.

    Извлекает top-level `mcpServers` (глобальные per-user серверы) и
    `projects[<path>].mcpServers` для каждого проекта.
    """
    if not claude_json_path.exists():
        return []
    try:
        data = json.loads(claude_json_path.read_text())
    except (json.JSONDecodeError, OSError):
        return []
    if not isinstance(data, dict):
        return []

    out: list[McpServerEntry] = []
    src_base = str(claude_json_path)

    # `~/.claude.json` — персональный файл разработчика в его домашней папке,
    # он не коммитится и не раздаётся организацией. Значит и top-level, и
    # per-project секции внутри него — это scope=user («поставил себе сам»),
    # даже когда запись привязана к конкретному проекту.
    top = data.get("mcpServers") or {}
    if isinstance(top, dict):
        for name, spec in top.items():
            entry = _entry_from_spec(name, spec, f"{src_base}:mcpServers", scope="user")
            if entry:
                out.append(entry)

    projects = data.get("projects") or {}
    if isinstance(projects, dict):
        for proj_path, proj_data in projects.items():
            if not isinstance(proj_data, dict):
                continue
            servers = proj_data.get("mcpServers") or {}
            if not isinstance(servers, dict):
                continue
            for name, spec in servers.items():
                entry = _entry_from_spec(
                    name, spec, f"{src_base}:projects[{proj_path}]", scope="user"
                )
                if entry:
                    out.append(entry)
    return out


# Куда плагин может положить свой MCP-конфиг внутри папки установки. Проверяем
# несколько кандидатов, потому что жёсткого стандарта нет: `.mcp.json` в корне
# плагина (тот же формат, что и у проекта), его вариант под `.claude/`, и
# манифест `.claude-plugin/plugin.json`, куда часть плагинов кладёт `mcpServers`
# вместе с остальными метаданными. Файла нет — просто пусто, ничего не ломается.
_PLUGIN_MCP_CANDIDATES: tuple[str, ...] = (
    ".mcp.json",
    ".claude/.mcp.json",
    ".claude-plugin/plugin.json",
)


def extract_from_plugins(claude_home: Path) -> list[McpServerEntry]:
    """MCP-серверы, приехавшие вместе с установленным плагином.

    Привязка «артефакт → плагин → маркетплейс» делается ровно тем же способом,
    что уже работает для skills и sub-agents: индекс установленных плагинов
    (`~/.claude/plugins/installed_plugins.json`) даёт installPath каждого
    плагина, а дальше внутри этой папки ищется MCP-конфиг. Это и есть ответ на
    «откуда MCP тянется»: origin=plugin + имя плагина + маркетплейс.

    Плагины ставятся в домашнюю папку разработчика, поэтому scope=user.
    """
    from ccguard.agent.scan.plugins import plugin_install_index

    out: list[McpServerEntry] = []
    seen: set[tuple[str, str]] = set()  # (name, plugin) — один плагин, одно имя
    for install_path, plugin_name, marketplace in plugin_install_index(claude_home):
        for rel in _PLUGIN_MCP_CANDIDATES:
            entries = _extract_from_mcp_json_file(
                install_path / rel,
                source_label=f"plugin:{plugin_name}@{marketplace}:{rel}",
                scope="user",
                origin="plugin",
                parent_plugin=plugin_name,
                source_marketplace=marketplace,
            )
            for e in entries:
                key = (e.name, plugin_name)
                if key not in seen:
                    seen.add(key)
                    out.append(e)
    return out
