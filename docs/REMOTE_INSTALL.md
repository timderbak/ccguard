# Установка ccguard на удалённый VPS

Эта инструкция поднимает `ccguard-server` на чистой Ubuntu/Debian-машине
и подключает к нему агент с dev-машины. Цель — получить рабочий стек
за один проход, без CI и без публичного домена.

## TL;DR — одна команда для 176.124.212.227

```bash
# 1. С dev-машины. ВАЖНО: если SSH ругается "REMOTE HOST IDENTIFICATION HAS CHANGED" —
#    см. секцию "Подводные камни" ниже. НЕ удаляй ключ автоматически.

# 2. Поставить docker на VPS (если ещё нет) и склонировать репо
ssh root@176.124.212.227 'apt-get update -qq && \
  apt-get install -y -qq docker.io docker-compose-plugin git openssl curl'
ssh root@176.124.212.227 'mkdir -p /opt/ccguard && cd /opt/ccguard && \
  (git clone https://github.com/timderbak/ccguard.git . 2>/dev/null || git pull) && \
  bash scripts/install-server.sh'

# 3. Достать токен агента
ssh root@176.124.212.227 'grep -E "^(CCGUARD_ADMIN_USER|CCGUARD_ADMIN_PASSWORD_PLAINTEXT|CCGUARD_TOKENS)=" /opt/ccguard/.env'

# 4. Поставить агент на dev-машине (из локального клона репо)
cd /Users/timderbak/dev/ccguard
SERVER_URL=http://176.124.212.227:8080 \
TOKEN=<значение CCGUARD_TOKENS> \
  bash scripts/install-agent.sh

# 5. Проверить
curl -fsS http://176.124.212.227:8080/health
open http://176.124.212.227:8080/admin   # логин admin + пароль из .env
```

> Репо пока приватный — `git clone https://github.com/...` на VPS сработает
> только если ты залогинился туда раньше или если репо публичный. Если ни
> того, ни другого — `scp` всю папку: `scp -r /Users/timderbak/dev/ccguard root@176.124.212.227:/opt/`
> и переходи сразу к `bash scripts/install-server.sh`.

---

## Что произойдёт

### На сервере (VPS)

`scripts/install-server.sh`:

1. Проверяет наличие `docker`, `docker compose`, `openssl`.
2. Создаёт каталоги `/opt/ccguard/{data,logs,config}`.
3. Если `config/server_policy.yaml` нет — копирует пример из `examples/policy.example.yaml`.
4. Если `.env` нет — генерирует:
   - **`CCGUARD_ADMIN_PASSWORD_PLAINTEXT`** — случайный 32-символьный пароль
     админа UI (хранится в `.env`, в контейнер не уходит — для тебя),
   - **`CCGUARD_ADMIN_PASSWORD_HASH`** — bcrypt-хеш того же пароля
     (генерируется через одноразовый `python:3.12-slim` контейнер с `passlib`),
   - **`CCGUARD_TOKENS`** — токен для агентов (24 байта hex),
   - **`CCGUARD_SESSION_SECRET`** — секрет для подписи cookies админ-UI.
   Файл создаётся с правами `600`.
5. Поднимает `docker compose -f docker/docker-compose.remote.yml up -d --build`.
6. Ждёт до 60 секунд, пока `/health` ответит 200.
7. Печатает креды и подсказку для установки агента.

Идемпотентно: повторный запуск **не** перегенерирует `.env`, **не**
сбрасывает SQLite. Просто пересоберёт образ и поднимет контейнер.

### На dev-машине

`scripts/install-agent.sh`:

1. Находит python ≥ 3.12.
2. Ставит пакет `ccguard` через `pip install --user` (из локального клона репо,
   если скрипт лежит внутри него, иначе — из git URL).
3. Пишет `~/.ccguard/config.yaml` с `server.url` + `server.token` (`chmod 600`).
   Сохраняет `install_salt`, если он уже был.
4. Запускает `ccguard install --scope user` — регистрирует PreToolUse hook
   в `~/.claude/settings.json` (если Claude Code установлен; если нет — skip).
5. Регистрирует daemon: launchd на macOS, systemd-user на Linux.
6. Делает первый `ccguard sync` — машина появляется в UI.

---

## Структура файлов на VPS

```
/opt/ccguard/
├── .env                         # секреты, chmod 600, НЕ коммитить
├── data/
│   └── ccguard.db               # SQLite WAL
├── logs/                        # серверные логи (если включены)
├── config/
│   └── server_policy.yaml       # активная policy (можно править на лету)
├── docker/
│   ├── Dockerfile.server
│   └── docker-compose.remote.yml
└── scripts/install-server.sh
```

Бэкап = `/opt/ccguard/{data,config,.env}`.

---

## Проверка что всё работает

На сервере:

```bash
ssh root@176.124.212.227 'curl -fsS http://localhost:8080/health'
# → {"status":"ok","policy_revision":1,"db":"ok"}

ssh root@176.124.212.227 'docker compose -f /opt/ccguard/docker/docker-compose.remote.yml ps'
# должно быть: ccguard-server  Up (healthy)
```

На dev-машине:

```bash
curl -fsS http://176.124.212.227:8080/health
ccguard sync
# → "sync ok, policy revision N, applied=..."
```

В браузере:

```
http://176.124.212.227:8080/admin    → логин/пароль из .env
http://176.124.212.227:8080/admin/machines   → твоя dev-машина должна быть видна
```

---

## Подводные камни

### 1. SSH `REMOTE HOST IDENTIFICATION HAS CHANGED`

Если ssh пишет:
```
@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
@    WARNING: REMOTE HOST IDENTIFICATION HAS CHANGED!     @
@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
Offending ECDSA key in /Users/timderbak/.ssh/known_hosts:3
```

— это значит, что host key VPS изменился (пересоздание машины, ротация ключа
или MITM). **Не удаляй ключ автоматически в скриптах** — это deструктивно
и может скрыть реальную атаку. Делай руками после визуальной проверки fingerprint'а:

```bash
# Удалить только этот хост из known_hosts:
ssh-keygen -R 176.124.212.227

# Или закомментировать строку 3 в ~/.ssh/known_hosts вручную.

# Затем подключиться — ssh запросит подтверждение нового fingerprint'а.
ssh root@176.124.212.227
```

### 2. Firewall на VPS

Стек открывает порт `8080` на хосте. Если на VPS активен `ufw` или iptables,
открой порт:

```bash
ssh root@176.124.212.227 'ufw allow 8080/tcp || iptables -I INPUT -p tcp --dport 8080 -j ACCEPT'
```

Для production без TLS наружу 8080 выставлять нежелательно — поставь
caddy/nginx на 443 и проксируй внутрь. См. TODO в `docker-compose.remote.yml`.

### 3. Docker без `compose plugin`

На старых Ubuntu (`docker-compose` вместо `docker compose`):

```bash
apt-get install -y docker-compose-plugin   # современный путь
# или
apt-get install -y docker-compose          # legacy v1 — скрипт работать НЕ будет
```

Скрипт проверяет `docker compose version` и упадёт с понятной ошибкой, если
plugin отсутствует.

### 4. bcrypt-хеш и `$` в `.env`

`docker-compose` интерполирует переменные `$X` из `.env`. bcrypt-хеши
содержат `$2b$12$…` — три `$`-знака, которые ломают интерполяцию. Скрипт
автоматически удваивает их (`$` → `$$`). Если правишь `.env` руками —
не забудь про это.

### 5. Репо приватный

Сейчас `git clone https://github.com/timderbak/ccguard.git` на VPS работает
только если у root настроены креды. Альтернатива — `scp -r` всего репо.
TODO: опубликовать репо или сделать deploy key.

### 6. `pip install --user` и PATH

На macOS пакет ставится в `~/Library/Python/3.12/bin/`, на Linux —
в `~/.local/bin`. Скрипт печатает предупреждение, если этот путь не в PATH.
Добавь в `~/.zshrc`/`~/.bashrc`:

```bash
export PATH="$HOME/.local/bin:$PATH"   # Linux
# или
export PATH="$HOME/Library/Python/3.12/bin:$PATH"   # macOS
```

### 7. Несколько агентов с одним токеном

В v0.2 один `CCGUARD_TOKENS` обслуживает всех агентов — машины
разделяются по `machine_id` (производный от `install_salt` в `~/.ccguard/config.yaml`).
Если хочешь раздельные токены — добавь их через запятую:
`CCGUARD_TOKENS=tok1,tok2,tok3`.

---

## Откат

```bash
ssh root@176.124.212.227 '
  cd /opt/ccguard && \
  docker compose -f docker/docker-compose.remote.yml down && \
  echo "БД и .env не тронуты — лежат в /opt/ccguard/data и /opt/ccguard/.env"
'
```

Полное удаление (с потерей БД):

```bash
ssh root@176.124.212.227 '
  cd /opt/ccguard && \
  docker compose -f docker/docker-compose.remote.yml down -v && \
  rm -rf /opt/ccguard
'
```
