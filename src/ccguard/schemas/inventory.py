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
    command_file_hash: str | None = None
    command_file_path: str | None = None
    # TOFU baseline / drift detection. None means "no info" (couldn't read,
    # inline command, etc); when set, one of {"missing", "permission_denied",
    # "too_large"} — explains why command_file_hash is None even though the
    # command appears to reference a file.
    file_unreadable_reason: str | None = None
    # v0.2 UX/forensics field. Agent sets True when the hook command (or its
    # script file's shebang block) carries a ccguard ownership marker, so the
    # /admin/machines/<id> UI can show "this hook is ours" vs "unknown — check
    # source". Default False keeps backward-compat with v0.1 agents that don't
    # populate the field.
    is_ccguard_owned: bool = False


class McpServerEntry(SchemaBase):
    name: str
    transport: Literal["stdio", "http", "sse"]
    command: str | None = None
    args: list[str] = []
    url: str | None = None
    env_keys: list[str] = []
    source: str
    # MCP rug pull detection (feat/mcp-rug-pull). All optional so older agents
    # (v0.1) that don't compute these continue to validate cleanly — server
    # treats missing values as "no baseline material" and skips diff.
    description: str | None = None
    description_hash: str | None = None
    definition_hash: str | None = None
    # P4b: hash of the server's RUNTIME tool list (name+description per tool),
    # the indirect-injection rug-pull surface that lives in tools/list, NOT in
    # the static config. Captured from a config `tools` array if present, or an
    # opt-in HTTP tools/list probe. None when unavailable (diff then skipped).
    tools_hash: str | None = None
    # Provenance (v0.3+) — "откуда этот MCP взялся", the transparency axis.
    # Two INDEPENDENT axes, mirroring SkillEntry/AgentEntry's source tracking:
    #
    #   scope  — WHERE the config is declared, i.e. WHO put it there:
    #     managed       = pushed centrally by the org (IT/security) — sanctioned;
    #     user          = the developer's own personal config — self-installed;
    #     project       = committed in the repo, ships with the code to the team;
    #     project_local = local-only project override, never committed.
    #   origin — WHETHER it came bundled with an installed plugin (plugin) or was
    #     declared by hand (local); when `plugin`, parent_plugin +
    #     source_marketplace name it, e.g. "claude-mem" @
    #     "anthropics/claude-plugins-official".
    #
    # All optional: a v0.1/v0.2 agent omits them and the server renders the row
    # as "источник неизвестен" rather than guessing.
    scope: Literal["user", "project", "project_local", "managed"] | None = None
    origin: Literal["local", "plugin"] = "local"
    parent_plugin: str | None = None
    source_marketplace: str | None = None


class SkillEntry(SchemaBase):
    name: str
    path: str
    origin: Literal["local", "marketplace", "plugin"]
    dir_hash: str
    has_referenced_scripts: bool
    # v0.3 source tracking. Optional so v0.1/v0.2 inventory payloads parse.
    # parent_plugin: имя плагина-родителя (без marketplace), source_marketplace:
    # marketplace-key (например "anthropics/claude-plugins-official"). Для
    # local-скиллов оба None. См. specs/2026-06-02-skills-agents-baseline-design.md.
    parent_plugin: str | None = None
    source_marketplace: str | None = None


class PluginEntry(SchemaBase):
    name: str
    source: str
    enabled: bool


class AgentEntry(SchemaBase):
    """Кастомный субагент: `~/.claude/agents/<name>.md` (local) или
    `<plugin_install_path>/agents/<name>.md` (plugin-bundled, v0.3+)."""

    name: str
    path: str
    file_hash: str
    tools: list[str] | None = None  # из YAML frontmatter `tools:` (если есть)
    model: str | None = None
    description: str | None = None
    # v0.3 source tracking — параллельно SkillEntry. До v0.3 агенты
    # сканировались только из ~/.claude/agents/, поэтому default "local".
    origin: Literal["local", "plugin"] = "local"
    parent_plugin: str | None = None
    source_marketplace: str | None = None


class CommandEntry(SchemaBase):
    """Кастомная slash-команда: `~/.claude/commands/[<ns>/]<name>.md`."""

    name: str  # `<ns>/<name>` без расширения
    path: str
    file_hash: str


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
    # v0.2 UX fields for /admin/machines/<id> inventory rendering. Optional so
    # v0.1 agents that don't compute them continue to validate cleanly.
    hooks_count: int | None = None
    size_bytes: int | None = None


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
    agents: list[AgentEntry] = []
    commands: list[CommandEntry] = []
    env_keys: list[str] = []  # имена переменных из settings.env (без значений)
    claude_code_version: str | None = None
