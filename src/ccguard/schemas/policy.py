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


class LlamaGuardConfig(SchemaBase):
    """Optional LlamaGuard backend for prompt-injection scanning (Phase 5 / 05-01).

    Self-hosted Ollama endpoint by default — single external dep is intentional
    (org runs `ollama serve` locally; no cloud-AI). `extra="ignore"` so a
    future server schema can add fields without breaking v0.2 agents (D-1
    backward-compat policy, inherited semantics).
    """

    model_config = ConfigDict(extra="ignore", str_strip_whitespace=True)

    enabled: bool = False
    endpoint: str = "http://localhost:11434"
    model: str = "llama-guard3:8b"
    # Bounded to keep PreToolUse hook latency budget (<100ms total, see CLAUDE.md).
    # CR-04: default lowered 500→150 and upper bound clamped 10000→200 so a
    # LlamaGuard scan cannot blow the 100ms SLA. Admins who need a longer
    # budget should switch to async/fire-and-forget (deferred to v0.3).
    timeout_ms: int = Field(default=150, ge=50, le=200)


class PromptInjectionConfig(SchemaBase):
    """Prompt-injection scanner config — additive section in Policy (Phase 5).

    schema_version stays at 1: this is an additive change. `extra="ignore"`
    locally on top of Policy-level `extra="ignore"` so any future sub-field
    (e.g., per-category severity overrides) does not break older agents.
    """

    model_config = ConfigDict(extra="ignore", str_strip_whitespace=True)

    enabled: bool = True
    severity: Literal["info", "warn", "block"] = "warn"
    regex_patterns: list[str] = Field(default_factory=list)
    allowlist_patterns: list[str] = Field(default_factory=list)
    llama_guard: LlamaGuardConfig = Field(default_factory=LlamaGuardConfig)


class SignalOverrideIn(SchemaBase):
    """One catalog signal pushed from the server (Rule Discovery Agent · E4).

    Mirrors :class:`ccguard.agent.signals.catalog.Signal` fields. ``pattern``
    is a Python regex string compiled with ``re.IGNORECASE`` on the agent.
    Invalid regex is silently dropped by the extractor — the admin's approve
    path validates ``re.compile`` so this is defense in depth.
    """

    id: str = Field(min_length=1, max_length=128)
    attack_technique: str = Field(min_length=1, max_length=64)
    pattern: str = Field(min_length=1, max_length=1024)
    description: str = Field(min_length=1, max_length=512)


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
    # Behavioral Detection Stage 5b: global enforcement mode.
    # ``observe`` (default) makes the agent log would-have-denied decisions
    # but allow the tool call through — closes the "remove all blocking" ask.
    # ``enforce`` restores the historical blocking behavior.
    enforcement_mode: Literal["observe", "enforce"] = "observe"
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
    # Phase 5 / 05-01: prompt-injection scanner config (PI-01..04 baseline).
    # Additive — schema_version stays 1. v0.1/v0.2 agents tolerate via Policy
    # `extra="ignore"`; field uses default_factory so policies without this
    # section parse cleanly.
    prompt_injection: PromptInjectionConfig = Field(default_factory=PromptInjectionConfig)
    # Rule Discovery Agent (E4): server-pushed catalog overrides. Each entry
    # is the same shape the catalog Signal uses; agent's extractor compiles
    # and merges these on top of the baked CATALOG (override-wins precedence
    # for same id). Empty by default → existing agents unaffected.
    signal_overrides: list[SignalOverrideIn] = Field(default_factory=list)
