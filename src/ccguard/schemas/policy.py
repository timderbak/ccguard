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


class SuspiciousHostRule(SchemaBase):
    """Realtime PreToolUse-проверка сетевого target'а (P1 — Suspicious network calls).

    Зеркало :class:`DangerousBashRule`, но для URL/hostname. Выделено в
    отдельный каталог потому что:

    * Цель не bash-команда, а URL — нужен URL-aware match
      (``discord.com/api/webhooks/*`` против host+path).
    * Спец-id'шники (``egress/ip-as-host``, ``egress/private-ip``) — это
      не fnmatch/regex, а вызов отдельного детектора в коде enforce.

    severity=warn → не блокирует, но добавляет signal-метку в
    EnforceDecision.warning_signals и попадает в finding-буфер.
    """

    id: str = Field(min_length=1, max_length=128)
    pattern: str = Field(min_length=1, max_length=1024)
    type: Literal["glob", "regex"] = "glob"
    severity: Literal["warn", "block"] = "block"
    title: str = Field(min_length=1, max_length=256)
    reason: str = Field(min_length=1, max_length=512)
    remediation: str = Field(min_length=1, max_length=512)


def _default_suspicious_host_rules() -> list[SuspiciousHostRule]:
    """Дефолтный набор Suspicious Host правил.

    Категории:

    * Pastebin-like — block (классический exfil/loader канал).
    * Discord/Telegram/Slack webhooks — block (bot API exfil).
    * Raw github gists — warn (часто легитимно: install скрипты, README).
    * IP-as-host — warn (часто легитимно: localhost/cnc-симптом).
    * Private IP — warn.

    Pattern для ip-as-host / private-ip — placeholder ``__detector__``:
    специальная логика в ``_decide_web`` обходит fnmatch/regex и
    использует ``detect_ip_as_host`` / ``is_private_ip``.
    """
    pastebin_hosts = [
        "pastebin.com",
        "*.pastebin.com",
        "paste.ee",
        "hastebin.com",
        "dpaste.com",
        "ix.io",
        "0x0.st",
        "transfer.sh",
        "pixeldrain.com",
    ]
    rules: list[SuspiciousHostRule] = []
    for host in pastebin_hosts:
        rules.append(
            SuspiciousHostRule(
                id="egress/pastebin",
                pattern=host,
                type="glob",
                severity="block",
                title="Загрузка с pastebin-подобного сервиса",
                reason=(
                    "Pastebin и аналоги — типичный канал доставки вредоносных "
                    "скриптов и exfiltration данных."
                ),
                remediation=(
                    "Если знаешь зачем именно этот ресурс — добавь его в "
                    "network.allowlist_hosts. Иначе откажи."
                ),
            )
        )
    rules.extend(
        [
            SuspiciousHostRule(
                id="egress/discord-webhook",
                pattern="discord.com/api/webhooks/*",
                type="glob",
                severity="block",
                title="Discord webhook",
                reason=(
                    "Discord webhook — популярный канал exfiltration: данные "
                    "уходят в чужой чат без аудита."
                ),
                remediation=(
                    "Используй внутренний коммуникационный канал организации."
                ),
            ),
            SuspiciousHostRule(
                id="egress/telegram-bot",
                pattern="api.telegram.org/bot*",
                type="glob",
                severity="block",
                title="Telegram bot API",
                reason=(
                    "Telegram Bot API — частый exfil-канал для stealer'ов и "
                    "RAT'ов."
                ),
                remediation=(
                    "Запрети по умолчанию. Если есть легитимный use-case — "
                    "явно добавь в allowlist."
                ),
            ),
            SuspiciousHostRule(
                id="egress/slack-webhook",
                pattern="hooks.slack.com/services/*",
                type="glob",
                severity="block",
                title="Slack incoming webhook",
                reason=(
                    "Slack webhook без аутентификации — exfil-вектор: данные "
                    "уходят в произвольный workspace."
                ),
                remediation=(
                    "Используй авторизованный Slack Bot вместо incoming webhook."
                ),
            ),
            SuspiciousHostRule(
                id="egress/raw-gist",
                pattern="raw.githubusercontent.com",
                type="glob",
                severity="warn",
                title="Скачивание raw-файла из GitHub gist/repo",
                reason=(
                    "raw.githubusercontent.com часто используется install-"
                    "скриптами и легитимен, но через него же доставляют "
                    "malware из вредоносных gists."
                ),
                remediation=(
                    "Проверь, что репозиторий/gist принадлежит ожидаемому "
                    "автору и содержимое выглядит безобидно."
                ),
            ),
            SuspiciousHostRule(
                id="egress/raw-gist",
                pattern="gist.githubusercontent.com",
                type="glob",
                severity="warn",
                title="Скачивание raw-файла из GitHub gist",
                reason=(
                    "gist.githubusercontent.com — частый канал доставки "
                    "одноразовых install-скриптов."
                ),
                remediation=(
                    "Проверь автора gist и содержимое перед запуском."
                ),
            ),
            SuspiciousHostRule(
                id="egress/ip-as-host",
                pattern="__detector__",
                type="regex",
                severity="warn",
                title="IP-адрес вместо доменного имени",
                reason=(
                    "Обращение по IP (особенно обфусцированному hex/decimal) "
                    "обходит DNS-логирование и часто признак CnC-связи."
                ),
                remediation=(
                    "Используй DNS-имя. Если IP легитимный — добавь его в "
                    "network.allowlist_hosts."
                ),
            ),
            SuspiciousHostRule(
                id="egress/private-ip",
                pattern="__detector__",
                type="regex",
                severity="warn",
                title="Обращение к private IP",
                reason=(
                    "Запросы на 10.*/172.16-31.*/192.168.*/127.* часто "
                    "легитимны (локальная разработка), но иногда — экспорт "
                    "к локальному CnC."
                ),
                remediation=(
                    "Если это локальный dev-сервер — добавь его в "
                    "network.allowlist_hosts, чтобы убрать шум."
                ),
            ),
        ]
    )

    # --- Curated IOC pack: exfil sinks, file-drops, tunnels, OOB-capture, mining
    # pools. Durable, FP-safe hosts an AI-agent exfil / cryptojacking would use.
    # paste / file-drop / anon-upload — block (exfil drop, extends pastebin set)
    file_drop_hosts = [
        "rentry.co", "controlc.com", "ghostbin.com", "termbin.com", "sprunge.us",
        "paste.rs", "dpaste.org", "bpa.st", "justpaste.it", "write.as", "privatebin.net",
        "file.io", "anonfiles.com", "gofile.io", "*.gofile.io", "catbox.moe", "litterbox.catbox.moe",
        "bashupload.com", "oshi.at", "temp.sh", "x0.at", "uguu.se", "ufile.io",
        "filebin.net", "tmpfiles.org", "krakenfiles.com", "easyupload.io",
    ]
    for host in file_drop_hosts:
        rules.append(SuspiciousHostRule(
            id="egress/file-drop", pattern=host, type="glob", severity="block",
            title="Anon file-drop / paste сервис",
            reason="Анонимные file-drop и paste-сервисы — типичный канал exfiltration данных.",
            remediation="Если ресурс нужен по делу — добавь в network.allowlist_hosts. Иначе откажи.",
        ))
    # OOB / webhook-capture — block (attacker inspectors, almost never legit egress)
    oob_hosts = [
        "webhook.site", "*.requestbin.com", "*.requestbin.net", "requestcatcher.com",
        "*.pipedream.net", "beeceptor.com", "*.interact.sh", "*.oast.fun", "*.oast.pro",
        "*.oast.live", "*.oast.site", "*.burpcollaborator.net", "hookbin.com", "smee.io",
    ]
    for host in oob_hosts:
        rules.append(SuspiciousHostRule(
            id="egress/oob-capture", pattern=host, type="glob", severity="block",
            title="Out-of-band / webhook-capture сервис",
            reason="Сервисы перехвата запросов (webhook.site / requestbin / interactsh) — каналы OOB-эксфильтрации и SSRF-подтверждения.",
            remediation="Легитимного повода слать данные агентом сюда почти нет. Откажи.",
        ))
    # tunnel / expose — warn (dual-use: devs legitimately tunnel localhost)
    tunnel_hosts = [
        "*.ngrok.io", "*.ngrok-free.app", "*.trycloudflare.com", "*.loca.lt",
        "localtunnel.me", "serveo.net", "localhost.run", "*.lhr.life", "bore.pub", "pagekite.me",
    ]
    for host in tunnel_hosts:
        rules.append(SuspiciousHostRule(
            id="egress/tunnel", pattern=host, type="glob", severity="warn",
            title="Tunnel / expose сервис",
            reason="Сервисы проброса (ngrok / cloudflared / localtunnel) бывают легитимны в dev, но также — канал reverse-access / exfil.",
            remediation="Если это твой dev-туннель — добавь в allowlist. Иначе разберись, кто его поднял.",
        ))
    # cryptomining pools — block (never legitimate from a dev endpoint)
    mining_hosts = [
        "*.minexmr.com", "pool.minexmr.com", "*.supportxmr.com", "*.nanopool.org",
        "*.moneroocean.stream", "*.hashvault.pro", "*.2miners.com", "*.nicehash.com",
        "*.f2pool.com", "ethermine.org", "*.c3pool.com", "xmrpool.eu", "*.zergpool.com",
    ]
    for host in mining_hosts:
        rules.append(SuspiciousHostRule(
            id="egress/mining-pool", pattern=host, type="glob", severity="block",
            title="Майнинг-пул",
            reason="Подключение к пулу криптомайнинга — resource hijacking (T1496); на dev-эндпоинте легитимного повода нет.",
            remediation="Найди процесс-майнер и удали. Это признак компрометации.",
        ))

    return rules


class NetworkPolicy(RuleBase):
    allowlist_hosts: list[str] = []
    denylist_hosts: list[str] = []
    deny_all_unknown: bool = False
    # P1 / Suspicious network calls: каталог подозрительных host'ов с
    # понятным «почему» и «что делать». Дефолты — factory'ём, чтобы
    # Pydantic не шарил mutable между Policy-инстансами.
    suspicious_host_rules: list[SuspiciousHostRule] = Field(
        default_factory=_default_suspicious_host_rules
    )


class DangerousBashRule(SchemaBase):
    """Realtime PreToolUse-блокировка опасных Bash-команд (P1 — Dangerous Bash Patterns).

    Отличие от ``always_deny`` / ``denylist_patterns`` — этот rule везёт с собой
    структурированный «почему опасно» / «что делать», чтобы UI рендерил
    карточку с понятным объяснением, а не голый regex. ``severity="warn"``
    не блокирует, но добавляет signal-метку в EnforceDecision и попадает в
    finding-буфер.

    Категории намеренно зеркалят упрощённый MITRE-набор для dev-эндпоинта;
    точное мэппинг на T#### делается в signal-catalog для PostToolUse audit'а.
    """

    id: str = Field(min_length=1, max_length=128)
    pattern: str = Field(min_length=1, max_length=1024)
    category: Literal["exfil", "destructive", "privilege-esc", "persistence", "tampering"]
    severity: Literal["warn", "block"] = "block"
    title: str = Field(min_length=1, max_length=256)
    reason: str = Field(min_length=1, max_length=512)
    remediation: str = Field(min_length=1, max_length=512)


def _default_dangerous_patterns() -> list[DangerousBashRule]:
    """Дефолтный набор Dangerous Bash правил.

    Минимум 8 правил, покрывающих основные сценарии: exfil, destructive,
    persistence, privilege-esc, tampering. Намеренно дублируется с PostToolUse
    signal catalog (cred.read.dotenv, system.permissive_chmod и т.п.) — цели
    разные: signal catalog аудит, dangerous_patterns enforce.
    """
    return [
        DangerousBashRule(
            id="exfil/curl-pipe-bash",
            pattern=r"curl\s+[^|]+\|\s*(sh|bash|zsh)\b",
            category="exfil",
            severity="block",
            title="Скачивание скрипта из интернета с исполнением",
            reason=(
                "curl | bash скачивает произвольный код и сразу его выполняет "
                "без возможности проверить содержимое."
            ),
            remediation=(
                "Скачай файл отдельно (curl -O), проверь содержимое, "
                "затем запусти. Или используй пакетный менеджер."
            ),
        ),
        DangerousBashRule(
            id="exfil/wget-pipe-bash",
            pattern=r"wget\s+[^|]+\|\s*(sh|bash|zsh)\b",
            category="exfil",
            severity="block",
            title="Скачивание скрипта из интернета через wget с исполнением",
            reason=(
                "wget | bash скачивает произвольный код и сразу его выполняет "
                "без возможности проверить содержимое."
            ),
            remediation=(
                "Скачай файл отдельно (wget -O), проверь содержимое, "
                "затем запусти."
            ),
        ),
        DangerousBashRule(
            id="destructive/rm-rf-root",
            pattern=r"\brm\s+(-[a-zA-Z]*[rRf][a-zA-Z]*\s+)+(/|~|\$HOME)(\s|$)",
            category="destructive",
            severity="block",
            title="Рекурсивное удаление корня или домашней директории",
            reason=(
                "rm -rf / (или ~ / $HOME) безвозвратно удалит критические "
                "файлы системы или весь твой профиль."
            ),
            remediation=(
                "Если действительно нужно удалить — укажи конкретный путь. "
                "Никогда не запускай rm -rf на / или ~."
            ),
        ),
        DangerousBashRule(
            id="persistence/ssh-authorized-keys",
            pattern=r"(>|>>)\s*~/\.ssh/authorized_keys",
            category="persistence",
            severity="block",
            title="Запись в ~/.ssh/authorized_keys",
            reason=(
                "Добавление ключа в authorized_keys даёт удалённый SSH-доступ "
                "и часто используется атакующим для закрепления."
            ),
            remediation=(
                "Если ты сам добавляешь ключ — сделай это вручную через "
                "редактор. AI-агенту не нужно править authorized_keys."
            ),
        ),
        DangerousBashRule(
            id="tampering/dotenv-read",
            pattern=r"\bcat\s+.*\.env\b|\bsource\s+.*\.env\b|\b(grep|less|head|tail)\s+.*\.env\b",
            category="tampering",
            severity="warn",
            title="Чтение .env с секретами",
            reason=(
                "В .env обычно лежат API-ключи и пароли. Их попадание в "
                "stdout-контекст AI-агента увеличивает риск утечки."
            ),
            remediation=(
                "Если ключи нужны агенту — передавай через переменные "
                "окружения, не показывай содержимое файла."
            ),
        ),
        DangerousBashRule(
            id="privilege-esc/sudo",
            pattern=r"\bsudo\s+(?!-n\b)",
            category="privilege-esc",
            severity="warn",
            title="Использование sudo",
            reason=(
                "sudo на dev-машине редко легитимен в контексте AI-агента и "
                "часто говорит о попытке эскалации привилегий."
            ),
            remediation=(
                "Подумай, нужны ли тебе root-права именно для этой задачи. "
                "Если да — запусти команду сам."
            ),
        ),
        DangerousBashRule(
            id="tampering/chmod-777",
            pattern=r"\bchmod\s+[0-7]?7[0-7]{2}\b",
            category="tampering",
            severity="warn",
            title="chmod с правами 777 / world-writable",
            reason=(
                "Полностью открытые права (777) на файл или директорию "
                "позволяют любому процессу их подменить."
            ),
            remediation=(
                "Используй более узкие права (644 для файлов, 755 для "
                "директорий)."
            ),
        ),
        DangerousBashRule(
            id="exfil/upload-pastebin",
            pattern=(
                r"\b(curl|wget|http)\s+.*"
                r"(pastebin\.com|paste\.ee|hastebin|transfer\.sh|0x0\.st|ix\.io|gist\.githubusercontent)"
            ),
            category="exfil",
            severity="block",
            title="Заливка данных на pastebin-подобный сервис",
            reason=(
                "Pastebin, transfer.sh и аналоги — классический канал "
                "exfiltration: данные уходят на внешний хост без аудита."
            ),
            remediation=(
                "Используй внутреннее хранилище организации. Если нужно "
                "поделиться кодом — gist через ваш корпоративный аккаунт."
            ),
        ),
    ]


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
    # P1 / Dangerous Bash Patterns (BACKLOG §4): структурированные правила
    # с понятным «почему» и «что делать» для realtime PreToolUse-блока.
    # Дефолты подгружаются factory, чтобы Pydantic не шарил mutable между
    # инстансами Policy.
    dangerous_patterns: list[DangerousBashRule] = Field(
        default_factory=_default_dangerous_patterns
    )


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
    # BACKLOG §6: Read-tool PI scanning. PostToolUse audit-scan of the file
    # content Claude just opened is always-on (the audit_hook unconditionally
    # invokes it); the two flags below are PreToolUse opt-ins:
    #   read_pi_block — when True + enforce mode, denies the Read if file
    #     content matches a default-catalog PI pattern. Default False because
    #     false positives in legitimate commercial code (mock injection
    #     strings in security tests, etc.) are annoying.
    #   read_pi_mask — when True, the PostToolUse hook attempts to mask the
    #     tool_response (best-effort; depends on Claude Code accepting
    #     hookSpecificOutput.updatedToolResponse — see docs/HOOKS_PROTOCOL.md).
    #     Default False; today this is a no-op pending upstream support.
    read_pi_block: bool = False
    read_pi_mask: bool = False


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
