"""Policy — схема политики организации."""

from __future__ import annotations

from datetime import datetime
from typing import Any, Literal

from ccguard.schemas._base import SchemaBase
from ccguard.schemas.finding import Severity


class RuleBase(SchemaBase):
    severity: Severity = "warn"


class McpServersPolicy(RuleBase):
    allowlist_names: list[str] = []
    denylist_names: list[str] = []
    allowlist_url_patterns: list[str] = []
    denylist_url_patterns: list[str] = []
    deny_all_unknown: bool = False


class NetworkPolicy(RuleBase):
    allowlist_hosts: list[str] = []
    denylist_hosts: list[str] = []
    deny_all_unknown: bool = False


class CommandsPolicy(RuleBase):
    denylist_patterns: list[str] = []
    allowlist_patterns: list[str] = []
    always_deny: list[str] = [
        r"\becho\s+.*>>\s*~/.bashrc",
        r"\becho\s+.*>>\s*~/.zshrc",
        r"\becho\s+.*>>\s*~/.profile",
        r"\bcurl\s+.*\|\s*(sh|bash)\b",
        r"\bwget\s+.*\|\s*(sh|bash)\b",
    ]


class SkillsPolicy(RuleBase):
    allowlist_names: list[str] = []
    trusted_dir_hashes: list[str] = []
    deny_all_unknown: bool = False
    signature: dict[str, Any] = {}


class HooksPolicy(RuleBase):
    allowlist_commands: list[str] = []
    deny_unknown: bool = True


class AgentsPolicy(RuleBase):
    """Кастомные субагенты (`~/.claude/agents/*.md`)."""

    allowlist_names: list[str] = []
    denylist_names: list[str] = []
    denylist_tools: list[str] = []
    trusted_file_hashes: list[str] = []
    deny_all_unknown: bool = False


class EnvPolicy(RuleBase):
    """Имена env-переменных в settings.json. Значения не инвентаризируются."""

    denylist_patterns: list[str] = []
    allowlist_names: list[str] = []


class PolicyMeta(SchemaBase):
    schema_version: Literal[1] = 1
    revision: int
    name: str = "default"
    updated_at: datetime


class Policy(SchemaBase):
    meta: PolicyMeta
    block_fail_mode: Literal["open", "closed"] = "open"
    mcp_servers: McpServersPolicy = McpServersPolicy()
    network: NetworkPolicy = NetworkPolicy()
    commands: CommandsPolicy = CommandsPolicy()
    skills: SkillsPolicy = SkillsPolicy()
    hooks: HooksPolicy = HooksPolicy()
    agents: AgentsPolicy = AgentsPolicy()
    env: EnvPolicy = EnvPolicy()
