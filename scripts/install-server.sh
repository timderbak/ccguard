#!/usr/bin/env bash
# install-server.sh — поднимает ccguard-server на свежей Ubuntu/Debian-машине
# через docker compose. Идемпотентен: повторный запуск не сбрасывает .env и БД.
#
# Использование на самом VPS (после копирования репо в /opt/ccguard):
#   cd /opt/ccguard && bash scripts/install-server.sh
#
# One-liner с dev-машины (см. docs/REMOTE_INSTALL.md):
#   ssh root@VPS 'mkdir -p /opt/ccguard && cd /opt/ccguard && \
#     git clone https://github.com/timderbak/ccguard.git . 2>/dev/null || git pull && \
#     bash scripts/install-server.sh'

set -euo pipefail

CCGUARD_DIR="${CCGUARD_DIR:-$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)}"
DATA_DIR="$CCGUARD_DIR/data"
LOG_DIR="$CCGUARD_DIR/logs"
CONFIG_DIR="$CCGUARD_DIR/config"
ENV_FILE="$CCGUARD_DIR/.env"
COMPOSE_FILE="$CCGUARD_DIR/docker/docker-compose.remote.yml"

log() { printf '\033[1;36m[ccguard]\033[0m %s\n' "$*"; }
die() { printf '\033[1;31m[ccguard] ERROR:\033[0m %s\n' "$*" >&2; exit 1; }

# --- 1. Sanity checks ------------------------------------------------------

command -v docker >/dev/null || die "docker не найден. На Ubuntu/Debian: apt-get install -y docker.io docker-compose-plugin"
docker compose version >/dev/null 2>&1 || die "docker compose plugin не установлен. apt-get install -y docker-compose-plugin"
command -v openssl >/dev/null || die "openssl не найден (нужен для генерации секретов)"

[[ -f "$COMPOSE_FILE" ]] || die "не найден $COMPOSE_FILE. Запускай скрипт из репозитория ccguard."

# --- 2. Каталоги -----------------------------------------------------------

mkdir -p "$DATA_DIR" "$LOG_DIR" "$CONFIG_DIR"

# Policy подкладываем с хоста: если её нет — берём пример из репо.
if [[ ! -f "$CONFIG_DIR/server_policy.yaml" ]]; then
    if [[ -f "$CCGUARD_DIR/examples/policy.example.yaml" ]]; then
        cp "$CCGUARD_DIR/examples/policy.example.yaml" "$CONFIG_DIR/server_policy.yaml"
        log "policy: скопирована из examples/policy.example.yaml → config/server_policy.yaml"
    else
        die "нет examples/policy.example.yaml и нет config/server_policy.yaml — положи свой policy.yaml в $CONFIG_DIR/"
    fi
fi

# --- 3. .env (генерируется один раз) ---------------------------------------

if [[ ! -f "$ENV_FILE" ]]; then
    log "генерирую $ENV_FILE с новыми секретами…"

    ADMIN_PASSWORD="$(openssl rand -hex 16)"
    AGENT_TOKEN="$(openssl rand -hex 24)"
    SESSION_SECRET="$(openssl rand -hex 32)"

    # bcrypt-хеш генерим через docker (чтобы не тащить python+passlib на хост).
    # ВНИМАНИЕ: $ в bcrypt-хеше нужно экранировать как $$ в .env для docker-compose.
    log "считаю bcrypt-хеш через одноразовый python:3.12-slim контейнер…"
    RAW_HASH="$(
        docker run --rm python:3.12-slim sh -c \
            "pip install --quiet 'passlib[bcrypt]' >/dev/null 2>&1 && \
             python -c 'import sys; from passlib.hash import bcrypt; print(bcrypt.hash(sys.argv[1]))' '$ADMIN_PASSWORD'"
    )" || die "не удалось сгенерировать bcrypt-хеш админ-пароля"
    # docker-compose интерполирует $X → подставит env. Экранируем $ → $$.
    ESCAPED_HASH="${RAW_HASH//\$/\$\$}"

    umask 077
    cat > "$ENV_FILE" <<EOF
# ccguard-server — сгенерировано install-server.sh $(date -u +%Y-%m-%dT%H:%M:%SZ)
# НЕ КОММИТИТЬ. Содержит секреты.

# --- админ UI ---
CCGUARD_ADMIN_USER=admin
# Пароль в чистом виде (НЕ передаётся в контейнер, нужен только тебе):
CCGUARD_ADMIN_PASSWORD_PLAINTEXT=${ADMIN_PASSWORD}
# bcrypt-хеш этого же пароля (для docker-compose, \$ удвоены):
CCGUARD_ADMIN_PASSWORD_HASH=${ESCAPED_HASH}

# --- сессии UI ---
CCGUARD_SESSION_SECRET=${SESSION_SECRET}
CCGUARD_COOKIE_SECURE=false

# --- агентский токен (отдаётся каждому ccguard-агенту) ---
CCGUARD_TOKENS=${AGENT_TOKEN}

# --- сеть ---
CCGUARD_SERVER_PORT=8080
CCGUARD_LOG_LEVEL=INFO

# --- опционально: LLM-сканер MCP/skills ---
# ANTHROPIC_API_KEY=sk-ant-...
EOF
    log "создан $ENV_FILE с правами 600."
else
    log ".env уже существует — повторно не генерирую."
fi

# --- 4. Подъём стека -------------------------------------------------------

cd "$CCGUARD_DIR"

log "docker compose up -d --build (это займёт 1–3 мин при первом запуске)…"
docker compose -f "$COMPOSE_FILE" --env-file "$ENV_FILE" up -d --build

log "жду healthcheck (до 60s)…"
deadline=$(( $(date +%s) + 60 ))
while (( $(date +%s) < deadline )); do
    if curl -fsS "http://localhost:${CCGUARD_SERVER_PORT:-8080}/health" >/dev/null 2>&1; then
        log "сервер ответил на /health"
        break
    fi
    sleep 2
done

# --- 5. Сводка для пользователя -------------------------------------------

echo
log "ccguard-server поднят."
echo
echo "  URL:        http://$(hostname -I 2>/dev/null | awk '{print $1}' || echo localhost):${CCGUARD_SERVER_PORT:-8080}"
echo "  Health:     curl -s http://localhost:${CCGUARD_SERVER_PORT:-8080}/health"
echo "  Логи:       docker compose -f docker/docker-compose.remote.yml logs -f"
echo "  Стоп:       docker compose -f docker/docker-compose.remote.yml down"
echo
echo "Креды (хранятся в $ENV_FILE):"
grep -E '^(CCGUARD_ADMIN_USER|CCGUARD_ADMIN_PASSWORD_PLAINTEXT|CCGUARD_TOKENS)=' "$ENV_FILE"
echo
echo "Дальше — установи агент на dev-машине:"
echo "  SERVER_URL=http://<vps-ip>:${CCGUARD_SERVER_PORT:-8080} \\"
echo "  TOKEN=\$(grep '^CCGUARD_TOKENS=' $ENV_FILE | cut -d= -f2) \\"
echo "  bash scripts/install-agent.sh"
