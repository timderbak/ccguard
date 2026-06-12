"""Opt-in HTTP MCP tools/list probe (P4b).

The MCP rug-pull surface is the RUNTIME tool list (each tool's name +
description), which lives in ``tools/list`` — NOT in the static ``.mcp.json``
config. Claude Code does not persist resolved tool definitions to disk, so the
only way to observe them is to ask the server.

This probe queries HTTP/SSE-transport MCP servers ONLY. It deliberately NEVER
spawns stdio servers: launching a potentially-malicious local server process
from the security agent is itself a risk, so stdio rug-pull capture is out of
scope here (config-embedded `tools` arrays still cover the case where the
definition is on disk).

Best-effort and fail-safe: any error, timeout, non-200, or unsupported
handshake returns ``None`` — the server then stores no ``tools_hash`` and the
baseline diff is simply skipped (same as a pre-P4b agent). OFF by default; a
runner enables it via ``CCGUARD_MCP_PROBE`` and passes the per-server url/headers.
"""
from __future__ import annotations

import json
import os
from typing import Any

import httpx

from ccguard.agent.scan.mcp import tools_hash

_DEFAULT_TIMEOUT = 4.0


def is_enabled() -> bool:
    """True only when the operator explicitly opted in (CCGUARD_MCP_PROBE)."""
    return os.environ.get("CCGUARD_MCP_PROBE", "").strip().lower() in {"1", "true", "yes"}


def _extract_tools(resp: httpx.Response) -> list | None:
    """Pull ``result.tools`` from a JSON or SSE (data:) MCP response."""
    payload: Any = None
    ctype = resp.headers.get("content-type", "")
    text = resp.text
    if "text/event-stream" in ctype or text.lstrip().startswith("data:"):
        for line in text.splitlines():
            line = line.strip()
            if line.startswith("data:"):
                try:
                    payload = json.loads(line[5:].strip())
                    break
                except (ValueError, TypeError):
                    continue
    if payload is None:
        try:
            payload = resp.json()
        except (ValueError, TypeError):
            return None
    if not isinstance(payload, dict):
        return None
    result = payload.get("result")
    if isinstance(result, dict) and isinstance(result.get("tools"), list):
        return result["tools"]
    return None


def probe_tools_hash(
    url: str | None,
    headers: dict | None = None,
    *,
    timeout: float = _DEFAULT_TIMEOUT,
    client: httpx.Client | None = None,
) -> str | None:
    """POST a JSON-RPC ``tools/list`` to an HTTP MCP server and hash the result.

    Returns a ``tools_hash`` on success, or ``None`` on ANY failure (fail-safe).
    Never raises. ``client`` is injectable for tests.
    """
    if not url:
        return None
    body = {"jsonrpc": "2.0", "id": 1, "method": "tools/list", "params": {}}
    hdrs = {
        "Content-Type": "application/json",
        "Accept": "application/json, text/event-stream",
    }
    if isinstance(headers, dict):
        hdrs.update({str(k): str(v) for k, v in headers.items()})
    try:
        if client is not None:
            resp = client.post(url, json=body, headers=hdrs, timeout=timeout)
        else:
            resp = httpx.post(url, json=body, headers=hdrs, timeout=timeout)
    except (httpx.HTTPError, httpx.TimeoutException):
        return None
    except Exception:  # noqa: BLE001 — probe must never raise into the scan
        return None
    if resp.status_code != 200:
        return None
    tools = _extract_tools(resp)
    return tools_hash(tools)
