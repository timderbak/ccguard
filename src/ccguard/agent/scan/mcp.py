"""Извлечение MCP-серверов из settings.json и .mcp.json."""

from __future__ import annotations

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
    """Order-independent hash of a runtime tool list (name+description per tool).

    The rug-pull surface lives here (tool descriptions are fed to the LLM as
    authoritative instructions). Returns None when no usable tool list exists,
    so the baseline diff is simply skipped (back-compat with no-tools agents).
    """
    if not isinstance(tools, list) or not tools:
        return None
    parts: list[str] = []
    for t in tools:
        if not isinstance(t, dict):
            continue
        name = str(t.get("name", ""))
        desc = str(t.get("description", ""))
        parts.append(f"{name}\x1f{desc}")
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


def _entry_from_spec(name: str, spec: dict[str, Any], source: str) -> McpServerEntry | None:
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
            entry = _entry_from_spec(name, spec, p.source.path)
            if entry is not None and (entry.name, entry.source) not in seen:
                out.append(entry)
                seen.add((entry.name, entry.source))
    return out


def _extract_from_mcp_json_file(path: Path, source_label: str | None = None) -> list[McpServerEntry]:
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
        entry = _entry_from_spec(name, spec, src)
        if entry:
            out.append(entry)
    return out


def extract_from_mcp_json(project_dir: Path) -> list[McpServerEntry]:
    """`.mcp.json` в корне проекта — альтернативный формат."""
    return _extract_from_mcp_json_file(project_dir / ".mcp.json")


def extract_from_user_mcp_json(claude_home: Path) -> list[McpServerEntry]:
    """Per-user `~/.claude/.mcp.json` — глобальный MCP-конфиг."""
    return _extract_from_mcp_json_file(claude_home / ".mcp.json")


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

    top = data.get("mcpServers") or {}
    if isinstance(top, dict):
        for name, spec in top.items():
            entry = _entry_from_spec(name, spec, f"{src_base}:mcpServers")
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
                entry = _entry_from_spec(name, spec, f"{src_base}:projects[{proj_path}]")
                if entry:
                    out.append(entry)
    return out
