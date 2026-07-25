#!/usr/bin/env bash
# One-command demo environment: seed EVERY finding tier into a throwaway DB,
# then serve. The console comes up already full of realistic, deterministic
# data — no hourly-scheduler wait, no juggling seed scripts, no manual machine
# registration. This is the bench for "see the product working" and the
# 12-minute colleague demo.
#
# UI:    http://127.0.0.1:8080   ·   login admin / admin   ·   agent token demo-token
#
# Override the DB with CCGUARD_DB_URL=..., the port with CCGUARD_PORT=...
set -euo pipefail
cd "$(dirname "$0")/.."

export CCGUARD_DB_URL="${CCGUARD_DB_URL:-sqlite:///./ccguard-demo.db}"
export CCGUARD_ADMIN_USER=admin
export CCGUARD_SESSION_SECRET=dev-secret
export CCGUARD_HOST=127.0.0.1
export CCGUARD_PORT="${CCGUARD_PORT:-8080}"
export CCGUARD_TOKENS=demo-token
export CCGUARD_ADMIN_PASSWORD_HASH="$(uv run python -c 'import bcrypt;print(bcrypt.hashpw(b"admin",bcrypt.gensalt()).decode())')"

# Fresh DB each run for a clean demo (the seeder is also idempotent, so this is
# just to drop any unrelated leftover rows). Only touches local sqlite files.
case "$CCGUARD_DB_URL" in
  sqlite:///*) f="${CCGUARD_DB_URL#sqlite:///}"; rm -f "$f" "$f-journal" "$f-wal" "$f-shm" ;;
esac

echo "→ seeding demo data (every finding tier)…"
uv run python scripts/demo-env.py

echo
echo "→ starting server on http://$CCGUARD_HOST:$CCGUARD_PORT   (login admin / admin)"
exec uv run ccguard-server
