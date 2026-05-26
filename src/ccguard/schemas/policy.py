"""Policy — схема политики организации."""

from __future__ import annotations

import re
from datetime import datetime
from typing import Any, Literal

from pydantic import ConfigDict, Field, field_validator

from ccguard.schemas._base import SchemaBase
from ccguard.schemas.finding import Severity

# kebab-case: lowercase letters/digits, dash-separated, no leading/trailing/double dash.
_KEBAB_RE = re.compile(r"^[a-z0-9]+(-[a-z0-9]+)*$")

# Safe single-segment identifier for filesystem path construction
# (CR-01, Phase 4 review): alphanumeric + underscore + dot + hyphen, max 64
# chars, must start with an alphanumeric. Used for RequiredSkill.name and
# RequiredAgent.name which are interpolated into paths under ~/.claude/.
# Bans path separators, leading dots (no "."/".."), absolute paths.
_SAFE_NAME_RE = re.compile(r"^[a-zA-Z0-9][a-zA-Z0-9_.-]{0,63}$")


def _validate_safe_name(v: str) -> str:
    """Reject any value that could escape a single path segment.

    Defense for CR-01 (Phase 4 review): RequiredSkill.name / RequiredAgent.name
    are interpolated into ``~/.claude/skills/<name>/SKILL.md`` and
    ``~/.claude/agents/<name>.md`` on the agent. A value like ``"../etc"`` or
    ``"/abs/path"`` would escape the sandbox. Enforce schema-level so both
    server publish and agent re-validate (see WR-03) reject it.
    """
    if v in {".", ".."} or "/" in v or "\\" in v or not _SAFE_NAME_RE.match(v):
        raise ValueError(
            f"name must be a safe single-segment identifier "
            f"(^[a-zA-Z0-9][a-zA-Z0-9_.-]{{0,63}}$, no '/', no '..'): {v!r}"
        )
    return v


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


class RequiredMCPServer(SchemaBase):
    """Mandatory MCP-сервер для установки агентом (Phase 4 / PUSH-01).

    `args` / `env` — единый JSON textarea на UI (D-6), хранятся плоско.
    Метка `_managed_by: "ccguard"` инжектится сервером при сохранении draft из
    /policy/mandatory (Phase 4 / 04-02, D-7). Поле опциональное в схеме, чтобы
    v0.1-агенты, не знающие про эту метку, продолжали валидировать политику —
    но при `model_dump(mode="json")` оно сериализуется и попадает в ответ
    /api/v1/policy, где агент plan 03 использует его в merge-логике.
    """

    name: str
    command: str
    args: list[str] = Field(default_factory=list)
    env: dict[str, str] = Field(default_factory=dict)
    # D-7: maintained by ccguard server; admins never set this in the UI.
    managed_by: str | None = Field(default=None, alias="_managed_by")

    model_config = ConfigDict(
        extra="forbid",
        str_strip_whitespace=True,
        frozen=False,
        populate_by_name=True,
        # Serialize using the alias so JSON keeps `_managed_by` exactly.
        serialize_by_alias=True,
    )


class RequiredSkill(SchemaBase):
    """Mandatory skill-файл (`~/.claude/skills/<name>/SKILL.md`) — PUSH-02.

    `content` хранит ПОЛНЫЙ текст файла (frontmatter + тело) единым полем
    (locked D-5: один textarea без отдельного редактора frontmatter).
    """

    name: str
    frontmatter_type: str = "skill"
    content: str

    @field_validator("name")
    @classmethod
    def _safe_name(cls, v: str) -> str:
        return _validate_safe_name(v)


class RequiredAgent(SchemaBase):
    """Mandatory subagent (`~/.claude/agents/<name>.md`) — PUSH-03."""

    name: str
    content: str

    @field_validator("name")
    @classmethod
    def _safe_name(cls, v: str) -> str:
        return _validate_safe_name(v)


class ManagedClaudeMdBlock(SchemaBase):
    """Управляемая секция в пользовательском `~/.claude/CLAUDE.md` — PUSH-04.

    `id` — стабильный kebab-case-идентификатор. Используется как маркер для
    обнаружения/обновления блока между sync-ами (`<!-- ccguard:block:<id> -->`).
    """

    id: str
    description: str = ""
    content: str

    @field_validator("id")
    @classmethod
    def _validate_kebab_id(cls, v: str) -> str:
        if not _KEBAB_RE.match(v):
            raise ValueError(
                f"id must be kebab-case (^[a-z0-9]+(-[a-z0-9]+)*$); got: {v!r}"
            )
        return v


class Policy(SchemaBase):
    # Backward-compat (D-1): v0.1-агенты, принимающие будущую расширенную политику,
    # должны игнорировать неизвестные поля верхнего уровня вместо ошибки валидации.
    # SchemaBase по умолчанию ставит extra='forbid' — здесь override на 'ignore'.
    model_config = ConfigDict(
        extra="ignore",
        str_strip_whitespace=True,
        frozen=False,
    )

    meta: PolicyMeta
    block_fail_mode: Literal["open", "closed"] = "open"
    mcp_servers: McpServersPolicy = McpServersPolicy()
    network: NetworkPolicy = NetworkPolicy()
    commands: CommandsPolicy = CommandsPolicy()
    skills: SkillsPolicy = SkillsPolicy()
    hooks: HooksPolicy = HooksPolicy()
    agents: AgentsPolicy = AgentsPolicy()
    env: EnvPolicy = EnvPolicy()
    # Phase 4 / PUSH-01..04: mandatory-sections — additive (schema_version stays 1).
    required_mcp_servers: list[RequiredMCPServer] = Field(default_factory=list)
    required_skills: list[RequiredSkill] = Field(default_factory=list)
    required_agents: list[RequiredAgent] = Field(default_factory=list)
    managed_claude_md_blocks: list[ManagedClaudeMdBlock] = Field(default_factory=list)
