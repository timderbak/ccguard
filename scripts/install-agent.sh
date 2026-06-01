#!/usr/bin/env bash
# install-agent.sh — ставит ccguard-агент на dev-машину (Linux/macOS),
# прописывает server.url+token в ~/.ccguard/config.yaml, регистрирует
# launchd/systemd-user daemon, делает первый sync.
#
# Использование:
#   SERVER_URL=http://78.17.68.120:8080 TOKEN=<agent-token> \
#     bash scripts/install-agent.sh
#
# Или curl-pipe (когда репо публичный):
#   curl -sL https://raw.githubusercontent.com/timderbak/ccguard/master/scripts/install-agent.sh \
#     | SERVER_URL=http://x.y.z.q:8080 TOKEN=xxx bash
#
# TODO(repo-public): пока репо приватный, curl-pipe из GitHub не работает —
# нужно либо опубликовать репо, либо ставить через git+ssh, либо запускать
# скрипт из локального клона как сейчас.

set -euo pipefail

: "${SERVER_URL:?SERVER_URL обязателен, например http://78.17.68.120:8080}"
: "${TOKEN:?TOKEN обязателен (значение CCGUARD_TOKENS с сервера)}"

CCGUARD_AGENT_HOME="${CCGUARD_AGENT_HOME:-$HOME/.ccguard}"
INSTALL_SOURCE="${INSTALL_SOURCE:-}"  # путь к локальному репо или git+https://... (см. ниже)

log() { printf '\033[1;36m[ccguard-agent]\033[0m %s\n' "$*"; }
die() { printf '\033[1;31m[ccguard-agent] ERROR:\033[0m %s\n' "$*" >&2; exit 1; }

# --- 1. Python 3.12 --------------------------------------------------------

PYTHON_BIN="${PYTHON_BIN:-}"
if [[ -z "$PYTHON_BIN" ]]; then
    for cand in python3.12 python3 python; do
        if command -v "$cand" >/dev/null 2>&1; then
            ver="$("$cand" -c 'import sys; print("%d.%d" % sys.version_info[:2])' 2>/dev/null || echo "0.0")"
            major="${ver%.*}"; minor="${ver#*.}"
            if (( major > 3 || ( major == 3 && minor >= 12 ) )); then
                PYTHON_BIN="$cand"
                break
            fi
        fi
    done
fi
[[ -n "$PYTHON_BIN" ]] || die "не найден python >= 3.12. Поставь его и повтори."

log "использую python: $PYTHON_BIN ($("$PYTHON_BIN" --version 2>&1))"

# --- 2. Установка пакета ---------------------------------------------------

if [[ -z "$INSTALL_SOURCE" ]]; then
    # Если скрипт лежит внутри клонированного репо — ставим из него.
    SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
    REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
    if [[ -f "$REPO_ROOT/pyproject.toml" ]] && grep -q '"ccguard"' "$REPO_ROOT/pyproject.toml" 2>/dev/null; then
        INSTALL_SOURCE="$REPO_ROOT"
    else
        # TODO(repo-public): заменить на https://github.com/timderbak/ccguard.git
        # когда репо опубликован.
        INSTALL_SOURCE="git+https://github.com/timderbak/ccguard.git"
    fi
fi

log "ставлю пакет из $INSTALL_SOURCE (--user)…"
"$PYTHON_BIN" -m pip install --user --upgrade "$INSTALL_SOURCE"

# user-base/bin — туда pip кладёт CLI-точки
USER_BIN="$("$PYTHON_BIN" -c 'import sysconfig; print(sysconfig.get_path("scripts", f"{sysconfig.get_default_scheme()}_user"))')"
if [[ ":$PATH:" != *":$USER_BIN:"* ]]; then
    log "PATH: добавь '$USER_BIN' в свой PATH (сейчас его там нет)."
fi

CCGUARD_CLI="$USER_BIN/ccguard"
[[ -x "$CCGUARD_CLI" ]] || CCGUARD_CLI="$PYTHON_BIN -m ccguard.agent.cli"

# --- 3. Конфиг агента ------------------------------------------------------

mkdir -p "$CCGUARD_AGENT_HOME"
CONFIG_PATH="$CCGUARD_AGENT_HOME/config.yaml"

# Сохраняем install_salt, если он уже был
EXISTING_SALT=""
if [[ -f "$CONFIG_PATH" ]]; then
    EXISTING_SALT="$(awk '/^install_salt:/ {print $2}' "$CONFIG_PATH" 2>/dev/null || echo "")"
fi

umask 077
{
    echo "server:"
    echo "  url: \"$SERVER_URL\""
    echo "  token: \"$TOKEN\""
    if [[ -n "$EXISTING_SALT" ]]; then
        echo "install_salt: $EXISTING_SALT"
    fi
} > "$CONFIG_PATH"
chmod 600 "$CONFIG_PATH"
log "конфиг записан: $CONFIG_PATH"

# --- 4. Установка хуков в Claude Code -------------------------------------

log "ccguard install --scope user (регистрация PreToolUse hook'а)…"
# shellcheck disable=SC2086
$CCGUARD_CLI install --scope user || log "install --scope user вернул ошибку — это нормально, если Claude Code не установлен. Пропускаю."

# --- 5. Регистрация daemon (launchd/systemd-user) -------------------------

log "регистрирую daemon (launchd/systemd-user)…"
"$PYTHON_BIN" - <<'PY' || log "daemon install не удался — это не критично, sync можно запускать вручную."
import sys
try:
    from ccguard.agent.daemon_install import install_daemon
    res = install_daemon(dry_run=False)
    print(f"daemon: {res}")
except Exception as exc:
    print(f"daemon install: {type(exc).__name__}: {exc}", file=sys.stderr)
    sys.exit(1)
PY

# --- 6. Первый sync --------------------------------------------------------

log "первый ccguard sync…"
# shellcheck disable=SC2086
$CCGUARD_CLI sync || die "sync не прошёл. Проверь SERVER_URL/TOKEN и доступность $SERVER_URL/health"

echo
log "готово."
echo "  Открой $SERVER_URL/admin (логин admin / пароль из .env на сервере)."
echo "  Машина должна появиться в списке."
echo "  Логи агента: ~/.ccguard/audit.log (и daemon-логи в ~/Library/Logs/ccguard или ~/.local/state/ccguard)"
