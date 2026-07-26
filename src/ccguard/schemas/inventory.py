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


class MemoryEntry(SchemaBase):
    """Файл памяти/инструкций, который Claude Code подгружает в контекст.

    Это CLAUDE.md на разных уровнях и всё, что он тянет через ``@import``.
    Такой файл — не конфигурация исполнения, а прямые инструкции агенту:
    закладка здесь («перед любой командой сначала сделай …») исполняется без
    единого подозрительного вызова, потому что для агента это его собственная
    память, а не входные данные. Именно поэтому память нужно инвентаризировать
    отдельно и следить за её дрейфом, как за хуками и скиллами.

    Содержимое НЕ передаётся и на сервере не хранится — только ``content_hash``.
    Причина та же, что у канареек: память легко содержит внутренние пути,
    секреты в примерах, имена систем. Для детекта дрейфа хватает отпечатка, а
    утечка базы сервера не должна раздавать чужие инструкции.
    """

    path: str
    # Уровень, на котором файл подхватывается. ``import`` — файл, притянутый
    # через @-ссылку из другого; ``subdir`` — CLAUDE.md во вложенном каталоге
    # проекта (грузится, когда агент туда заходит).
    scope: Literal[
        "enterprise", "user", "project", "project_local",
        "subdir", "ancestor", "import",
        # Прочие носители инструкций той же природы, что CLAUDE.md:
        "rules",          # .claude/rules/*.md — path-scoped правила
        "output_style",   # output-styles/*.md — расширяют системный промпт
        "managed_memory", # ключ claudeMd в managed-settings.json (политика орг.)
    ]
    content_hash: str
    size_bytes: int
    # Провенанс цепочки импортов: какой файл притянул этот через @import.
    # None — файл найден напрямую по известному пути, а не через ссылку.
    # Внешний импорт (из home, по абсолютному пути вне проекта) — сильный
    # сигнал: это способ спрятать инструкцию вне того, что ревьюят в репозитории.
    imported_by: str | None = None


class AutoMemoryStats(SchemaBase):
    """Признаки (features) файла АВТО-памяти Claude Code — той, что агент ведёт и
    переписывает САМ между сессиями (в отличие от CLAUDE.md, который пишет человек).

    Угроза (ASI06): отравленный текст, попавший в авто-память, персистит и влияет
    на будущие сессии с полномочиями самого агента — без единого подозрительного
    вызова, потому что для агента это его собственная память.

    Почему не hash-дрейф, как у CLAUDE.md: авто-память меняется КАЖДУЮ сессию
    легитимно — агент дописывает выученное. Baseline на content_hash кричал бы на
    каждый sync, оператор бы его отключил. Поэтому шлём числовые ПРИЗНАКИ, а
    сервер ловит АНОМАЛЬНУЮ ДЕЛЬТУ между соседними снимками: резкий вброс,
    появление внешних @import, всплеск атака-маркеров.

    По конституции проекта содержимое НЕ передаётся и не хранится — только
    счётчики и отпечаток. Признаки считаются на стороне агента.
    """

    path: str
    size_bytes: int = 0
    line_count: int = 0
    # Число ссылок вида @path (как в CLAUDE.md); авто-память обычно их не имеет.
    import_count: int = 0
    # Из них — наружу (абсолютный/домашний путь вне проекта): авто-память,
    # тянущая внешний файл, — аномалия сама по себе.
    external_import_count: int = 0
    # Число URL — скачок может означать вброшенный адрес эксфильтрации.
    url_count: int = 0
    # Узкий набор высокосигнальных атака-маркеров (curl|wget|base64 -d, ignore
    # previous, /etc/shadow, api_key и т.п.). Не «инструкции вообще» — только
    # технические маркеры атаки; ловим их СКАЧОК, не абсолютное присутствие.
    suspicious_marker_count: int = 0
    # Отпечаток — для «изменилось ли вообще», НЕ для дрейф-находки.
    content_hash: str = ""


class SandboxState(SchemaBase):
    """Эффективное состояние песочницы (sandbox — изолированной среды исполнения)
    Claude Code, слитое по всем scope'ам settings.json.

    Песочница — это периметр вокруг агента: что ему можно писать на диск, куда
    ходить по сети (egress-allowlist — список разрешённых исходящих доменов),
    какие команды бегают ВНЕ изоляции. Для ИБ важно не столько «включена ли»,
    сколько **не ослабили ли** её со временем: добавили домен в allowlist,
    разрешили команды вне песочницы, сняли fail-closed. Ослабление периметра —
    это Impair Defenses (ослабление защитного механизма, ATT&CK T1562) и
    Identity/Privilege Abuse (избыточные привилегии агента, OWASP ASI03).

    Все поля опциональны/с дефолтами: агент v0.1/v0.2 их не шлёт, и сервер
    принимает такой отчёт без ошибок (graceful degradation — мягкая деградация).
    Значение ``None`` у булевых полей значит «в конфиге не задано» и отличается
    от ``False`` («задано и выключено»).
    """

    # Есть ли ключ ``sandbox`` хоть в одном scope. Отличаем «выключена» от
    # «вообще не настроена» — это разные позы (posture), и на UI они не должны
    # выглядеть одинаково.
    configured: bool = False
    # sandbox.enabled — фундамент. False = песочницы фактически нет.
    enabled: bool | None = None
    # sandbox.failIfUnavailable — fail-closed (отказ в сторону «заблокировать»):
    # Claude Code откажется работать, если песочница недоступна. False/None =
    # fail-open (тихо работает БЕЗ песочницы) — слабее.
    fail_if_unavailable: bool | None = None
    # sandbox.allowUnsandboxedCommands — разрешить команды в обход изоляции.
    # True = дыра в периметре.
    allow_unsandboxed_commands: bool | None = None

    # --- сеть (egress) ---
    # sandbox.network.allowedDomains — egress-allowlist. Расширение = ослабление.
    network_allowed_domains: list[str] = []
    # sandbox.network.deniedDomains — явный чёрный список; снятие = ослабление.
    network_denied_domains: list[str] = []
    # sandbox.network.allowManagedDomainsOnly — только домены из managed-конфига;
    # сильнейшее ограничение egress, снятие = ослабление.
    network_allow_managed_domains_only: bool | None = None

    # --- файловая система ---
    # sandbox.filesystem.allowWrite — куда песочница пускает писать. Расширение =
    # ослабление.
    filesystem_allow_write: list[str] = []
    # sandbox.filesystem.denyRead — что скрыто от чтения (.ssh, .aws и т.п.).
    # Снятие пути = ослабление (агент снова видит секреты).
    filesystem_deny_read: list[str] = []
    # sandbox.filesystem.disabled — изоляция ФС выключена целиком.
    filesystem_disabled: bool | None = None

    # --- явные ослабляющие флаги Claude Code ---
    # sandbox.enableWeakerNestedSandbox / enableWeakerNetworkIsolation —
    # документированные «ослабленные» режимы. Включение = ослабление.
    weaker_nested_sandbox: bool | None = None
    weaker_network_isolation: bool | None = None

    # sandbox.excludedCommands — команды, исключённые из песочницы (docker и т.п.
    # по умолчанию). Расширение = больше кода вне наблюдения периметра.
    excluded_commands: list[str] = []

    # permissions.defaultMode — режим подтверждений по умолчанию. Не из блока
    # sandbox, но той же оси «сила периметра»: "bypassPermissions" = все
    # подтверждения выключены на уровне конфига (не CLI-флаг).
    default_mode: str | None = None

    # На каком scope задан итоговый ``enabled`` (managed важнее project_local
    # важнее project важнее user) — оператору видно, где «сильное слово».
    source_scope: str | None = None


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
    # Какой AI-агент инвентаризируется на этой машине. Строка, а не Literal:
    # новые агенты должны добавляться без изменения схемы (сервер graceful к
    # незнакомому значению). Известные: claude_code | cursor | copilot |
    # gemini_cli | codex_cli | aider | windsurf | other. Default — claude_code:
    # агент v0.1..v0.2 поля не шлёт, а до сих пор существовал только он.
    #
    # ВАЖНО: тип агента влияет на ВИДИМОСТЬ (что инвентаризуем), но НЕ на
    # enforcement. Блокировка <100мс держится на PreToolUse-хуке Claude Code,
    # которого у других агентов нет; для них ccguard даёт инвентарь и дрейф,
    # а не поведенческую блокировку. Это ограничение, а не недоработка.
    agent_kind: str = "claude_code"
    os: Literal["linux", "macos", "windows", "other"]
    settings_sources: list[SettingsSource] = []
    mcp_servers: list[McpServerEntry] = []
    skills: list[SkillEntry] = []
    hooks: list[HookEntry] = []
    plugins: list[PluginEntry] = []
    permissions: PermissionsSnapshot = PermissionsSnapshot()
    agents: list[AgentEntry] = []
    commands: list[CommandEntry] = []
    # Файлы памяти/инструкций (CLAUDE.md на всех уровнях + @import-цепочки).
    # Опционально: агент v0.1/v0.2 их не собирает и шлёт отчёт без поля —
    # сервер должен принимать такой отчёт без ошибок (graceful degradation).
    memory_files: list[MemoryEntry] = []
    # Эффективное состояние песочницы (sandbox on/off, egress-allowlist,
    # ослабляющие флаги). Опционально: агент v0.1/v0.2 поле не шлёт, сервер
    # принимает отчёт без него (graceful degradation). None — «не собрано».
    sandbox: SandboxState | None = None
    # Признаки файлов авто-памяти (та, что агент ведёт сам). Опционально: старый
    # агент не собирает и шлёт пустой список — сервер это принимает.
    auto_memory: list[AutoMemoryStats] = []
    env_keys: list[str] = []  # имена переменных из settings.env (без значений)
    claude_code_version: str | None = None
