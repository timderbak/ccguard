"""Inventory — нормализованный снимок конфигурации Claude Code."""

from __future__ import annotations

from datetime import datetime
from typing import Literal

from ccguard.schemas._base import SchemaBase


class HookEntry(SchemaBase):
    event: Literal[
        "PreToolUse",
        "PostToolUse",
        "SessionStart",
        "SessionEnd",
        "UserPromptSubmit",
        "Stop",
        "Notification",
        "SubagentStop",
        "PreCompact",
        "PostCompact",
    ]
    matcher: str | None = None
    type: Literal["command", "http", "mcp_tool", "prompt", "agent"]
    command: str | None = None
    url: str | None = None
    timeout_sec: int | None = None
    source: str


class McpServerEntry(SchemaBase):
    name: str
    transport: Literal["stdio", "http", "sse"]
    command: str | None = None
    args: list[str] = []
    url: str | None = None
    env_keys: list[str] = []
    source: str


class SkillEntry(SchemaBase):
    name: str
    path: str
    origin: Literal["local", "marketplace", "plugin"]
    dir_hash: str
    has_referenced_scripts: bool


class PluginEntry(SchemaBase):
    name: str
    source: str
    enabled: bool


class PermissionsSnapshot(SchemaBase):
    allow: list[str] = []
    deny: list[str] = []
    ask: list[str] = []
    dangerously_skip_detected: bool = False


class SettingsSource(SchemaBase):
    path: str
    scope: Literal["user", "project", "project_local", "managed"]
    exists: bool
    parse_error: str | None = None


class InventoryReport(SchemaBase):
    schema_version: Literal[1] = 1
    machine_id: str
    machine_label: str | None = None
    timestamp: datetime
    agent_version: str
    os: Literal["linux", "macos", "windows", "other"]
    settings_sources: list[SettingsSource] = []
    mcp_servers: list[McpServerEntry] = []
    skills: list[SkillEntry] = []
    hooks: list[HookEntry] = []
    plugins: list[PluginEntry] = []
    permissions: PermissionsSnapshot = PermissionsSnapshot()
    claude_code_version: str | None = None
