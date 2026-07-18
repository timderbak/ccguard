#!/usr/bin/env bash
# Локальный дев-сервер ccguard для ручного тестирования.
# UI: http://127.0.0.1:8080  ·  логин: admin / admin  ·  агентский токен: demo-token
set -euo pipefail
cd "$(dirname "$0")/.."

export CCGUARD_ADMIN_USER=admin
export CCGUARD_SESSION_SECRET=dev-secret
export CCGUARD_HOST=127.0.0.1
export CCGUARD_PORT=8080
export CCGUARD_TOKENS=demo-token
export CCGUARD_ADMIN_PASSWORD_HASH="$(uv run python -c 'import bcrypt;print(bcrypt.hashpw(b"admin",bcrypt.gensalt()).decode())')"

exec uv run ccguard-server
