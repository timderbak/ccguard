"""Извлечение MCP-серверов из settings.json и .mcp.json."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from ccguard.agent.scan.settings import ParsedSettings
from ccguard.schemas import McpServerEntry


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
    args = [str(a) for a in args_val] if isinstance(args_val, list) else []
    return McpServerEntry(
        name=name,
        transport=transport,  # type: ignore[arg-type]
        command=spec.get("command"),
        args=args,
        url=spec.get("url"),
        env_keys=env_keys,
        source=source,
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


def extract_from_mcp_json(project_dir: Path) -> list[McpServerEntry]:
    """`.mcp.json` в корне проекта — альтернативный формат."""
    mp = project_dir / ".mcp.json"
    if not mp.exists():
        return []
    try:
        data = json.loads(mp.read_text())
    except json.JSONDecodeError:
        return []
    if not isinstance(data, dict):
        return []
    servers = data.get("mcpServers") or {}
    if not isinstance(servers, dict):
        return []
    out: list[McpServerEntry] = []
    for name, spec in servers.items():
        entry = _entry_from_spec(name, spec, str(mp))
        if entry:
            out.append(entry)
    return out
