"""Приманки (канареечные токены): подложить фальшивый ключ и ждать.

Название — от канарейки в шахте: птица реагировала на газ раньше людей и тем
давала сигнал. Здесь так же: мы кладём на машину файл, который выглядит как
настоящий ключ доступа, но ничего не открывает.

Главное свойство — у такого файла НЕТ ни одного законного применения. Ни один
инструмент, ни один скрипт, ни один разработчик не имеет причин его читать: он
мёртв. Поэтому любое обращение означает, что кто-то целенаправленно ищет
секреты, и ложных срабатываний не бывает ПО ПОСТРОЕНИЮ — не потому, что мы
удачно подобрали правила, а потому что легитимного повода не существует. Это
редкость: почти все прочие детекты вынуждены балансировать между пропуском и
шумом.

Для агентской модели угроз приманка особенно уместна. Типовая атака через
инъекцию звучит как «собери переменные окружения и файлы с ключами» — агент
честно выполнит и наткнётся на приманку.

Два решения, важных для того, чтобы это вообще работало:

1. **Значение нигде не хранится**, только его sha256. Если база сервера утечёт
   вместе со значениями, атакующий получит список приманок и начнёт их
   обходить — а вся затея держится ровно на том, что отличить приманку от
   настоящего ключа он не может. Оператор видит значение один раз при создании.

2. **Детект не пишется заново.** При создании приманки заводится обычный
   :class:`ThreatIndicator` типа ``sensitive_path``; он уже раздаётся агентам
   вместе с политикой и превращается в сигнал ``cred.read.store_<id>``. То
   есть путь доставки и срабатывания — тот же, что у остальных чувствительных
   путей, здесь только особая трактовка результата.
"""
from __future__ import annotations

import hashlib
import logging
import secrets
import string
from dataclasses import dataclass
from datetime import UTC, datetime

from sqlmodel import Session, select

from ccguard.server.db.models import CanaryToken, ThreatIndicator

log = logging.getLogger(__name__)

# Источник индикаторов, заведённых приманками. Отдельное имя нужно, чтобы такие
# индикаторы не путались с настоящими чувствительными путями в отчётах.
CANARY_SOURCE = "canary"

_ALNUM = string.ascii_uppercase + string.digits
_LOWER_ALNUM = string.ascii_lowercase + string.digits


@dataclass(frozen=True)
class CanaryRecipe:
    """Как выглядит приманка данного типа и куда её класть."""

    token_type: str
    title: str
    default_path: str
    # Пояснение оператору: как именно разложить и почему это безопасно.
    instructions: str


# Форматы намеренно повторяют настоящие: приманка обязана быть неотличимой на
# вид, иначе атакующий (или модель, которую он направляет) её просто пропустит.
# Значения при этом случайны и ничего не открывают.
#
# ВАЖНО про пути. Приманку нельзя класть туда, где лежит НАСТОЯЩИЙ файл
# (~/.aws/credentials, ~/.ssh/id_rsa и т.п.): такие файлы законно читают сами
# инструменты — AWS CLI, ssh, gh, — и приманка начала бы срабатывать на обычной
# работе. Это разрушило бы её единственное ценное свойство: отсутствие ложных
# срабатываний по построению.
#
# Поэтому пути по умолчанию — соседние, «забытая копия»: они выглядят как
# оставленный второпях дубликат (именно за такими и охотятся), но ни один
# инструмент к ним не обращается.
RECIPES: dict[str, CanaryRecipe] = {
    "aws_key": CanaryRecipe(
        "aws_key",
        "Ключ доступа AWS",
        "~/.aws/credentials.bak",
        "Положи рядом с настоящим ~/.aws/credentials. Именно рядом, а НЕ вместо: "
        "настоящий файл законно читает AWS CLI, и приманка на его месте срабатывала "
        "бы при обычной работе. Копия с суффиксом .bak не нужна ни одному инструменту.",
    ),
    "github_pat": CanaryRecipe(
        "github_pat",
        "Токен GitHub",
        "~/.config/gh/hosts.yml.bak",
        "Рядом с рабочим конфигом gh, не вместо него: рабочий файл читает сам gh. "
        "Токен принадлежит несуществующему аккаунту.",
    ),
    "slack_token": CanaryRecipe(
        "slack_token",
        "Токен Slack",
        "~/.slack_token.old",
        "Файл в домашней папке с видом забытого старого токена — типичное место, "
        "куда их кладут и забывают.",
    ),
    "dotenv": CanaryRecipe(
        "dotenv",
        "Файл .env с секретами",
        "~/projects/.env.backup",
        "Положи рядом с рабочими проектами. Имя намеренно похоже на забытую "
        "резервную копию — именно такие файлы и ищут, а сборка их не читает.",
    ),
    "ssh_key": CanaryRecipe(
        "ssh_key",
        "Приватный ключ SSH",
        "~/.ssh/id_rsa_old",
        "Рядом с настоящими ключами, но НЕ под именем id_rsa: настоящий ключ "
        "постоянно читает ssh. Ключ нерабочий и никуда не пускает.",
    ),
}


def _rand(alphabet: str, n: int) -> str:
    return "".join(secrets.choice(alphabet) for _ in range(n))


def generate_value(token_type: str) -> str:
    """Сгенерировать правдоподобное, но заведомо нерабочее значение.

    Форматы соответствуют настоящим (длина, префикс, алфавит), потому что
    приманка должна выглядеть настоящей. Содержимое случайно — такого ключа не
    существует ни в одном сервисе, поэтому использовать его нельзя.
    """
    if token_type == "aws_key":
        # Формат AWS: AKIA + 16 символов. Ключ случайный — доступа не даёт.
        return f"AKIA{_rand(_ALNUM, 16)}"
    if token_type == "github_pat":
        return f"ghp_{_rand(string.ascii_letters + string.digits, 36)}"
    if token_type == "slack_token":
        return f"xoxb-{_rand(string.digits, 13)}-{_rand(string.digits, 13)}-{_rand(_LOWER_ALNUM, 24)}"
    if token_type == "dotenv":
        return f"sk_live_{_rand(string.ascii_letters + string.digits, 32)}"
    if token_type == "ssh_key":
        # Похоже на приватный ключ по обрамлению; тело — случайный мусор.
        body = "\n".join(_rand(string.ascii_letters + string.digits + "+/", 64) for _ in range(6))
        return f"-----BEGIN OPENSSH PRIVATE KEY-----\n{body}\n-----END OPENSSH PRIVATE KEY-----"
    raise ValueError(f"неизвестный тип приманки: {token_type}")


def render_file_content(token_type: str, value: str) -> str:
    """Готовое содержимое файла — чтобы оператору осталось только сохранить."""
    if token_type == "aws_key":
        return (
            "[default]\n"
            f"aws_access_key_id = {value}\n"
            f"aws_secret_access_key = {_rand(string.ascii_letters + string.digits + '/+', 40)}\n"
        )
    if token_type == "github_pat":
        return f"github.com:\n    oauth_token: {value}\n    user: ci-deploy\n"
    if token_type == "slack_token":
        return f"{value}\n"
    if token_type == "dotenv":
        return (
            f"STRIPE_SECRET_KEY={value}\n"
            f"DATABASE_URL=postgres://svc:{_rand(_LOWER_ALNUM, 16)}@db.internal:5432/prod\n"
        )
    if token_type == "ssh_key":
        return f"{value}\n"
    raise ValueError(f"неизвестный тип приманки: {token_type}")


def value_digest(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _path_to_pattern(file_path: str) -> str:
    """Путь → регулярное выражение для сопоставления в агенте.

    Агент сравнивает по нормализованному (приведённому к нижнему регистру)
    тексту, поэтому достаточно экранировать спецсимволы. Домашний каталог
    сворачивается в шаблон: у разных пользователей он разный, а имя файла —
    одно и то же.
    """
    import re

    p = file_path.strip()
    for prefix in ("~/", "$HOME/"):
        if p.startswith(prefix):
            p = p[len(prefix):]
            break
    return re.escape(p.lower())


@dataclass
class CreatedCanary:
    """Результат создания: сама приманка плюс значение и содержимое файла.

    Значение возвращается ЗДЕСЬ И ОДИН РАЗ — дальше в системе его нет.
    """

    token: CanaryToken
    value: str
    file_content: str
    instructions: str


def create_canary(
    session: Session,
    *,
    token_type: str,
    file_path: str | None = None,
    machine_id: str | None = None,
    label: str | None = None,
    created_by: str | None = None,
) -> CreatedCanary:
    """Создать приманку: сгенерировать значение, завести индикатор, сохранить хеш."""
    recipe = RECIPES.get(token_type)
    if recipe is None:
        raise ValueError(f"неизвестный тип приманки: {token_type}")
    path = (file_path or recipe.default_path).strip()
    if not path:
        raise ValueError("пустой путь приманки")

    value = generate_value(token_type)
    content = render_file_content(token_type, value)

    # Индикатор чувствительного пути — он и доставит детект на агенты.
    # source=canary (не os-standard), поэтому попадает в раздачу overrides.
    #
    # Индикатор описывает ПУТЬ, а приманок на одном пути может быть несколько —
    # например одна и та же приманка, разложенная на разные машины. Поэтому если
    # индикатор для этого пути уже заведён, он переиспользуется: раздавать
    # агентам два одинаковых правила незачем, да и уникальность
    # (тип, значение, источник) в хранилище это запрещает.
    pattern = _path_to_pattern(path)
    indicator = session.exec(
        select(ThreatIndicator)
        .where(ThreatIndicator.indicator_type == "sensitive_path")
        .where(ThreatIndicator.value == pattern)
        .where(ThreatIndicator.source == CANARY_SOURCE)
    ).first()
    if indicator is None:
        indicator = ThreatIndicator(
            indicator_type="sensitive_path",
            value=pattern,
            value_kind="regex",
            source=CANARY_SOURCE,
            source_ref=f"canary:{token_type}",
            technique="T1552.001",
            tactic="credential-access",
            weight=5.0,
            platform_relevant=True,
            status="active",  # приманку не нужно согласовывать — её завёл оператор
            enabled=True,
            description=f"Приманка ({recipe.title}) — обращение к ней означает поиск секретов",
        )
        session.add(indicator)
        session.commit()
        session.refresh(indicator)

    token = CanaryToken(
        token_type=token_type,
        file_path=path,
        machine_id=machine_id,
        value_sha256=value_digest(value),
        status="armed",
        label=label,
        indicator_id=indicator.id,
        created_by=created_by,
    )
    session.add(token)
    session.commit()
    session.refresh(token)
    return CreatedCanary(
        token=token, value=value, file_content=content, instructions=recipe.instructions
    )


def list_canaries(session: Session) -> list[CanaryToken]:
    """Все приманки: сработавшие сверху, дальше по времени создания."""
    rows = list(session.exec(select(CanaryToken)))
    rows.sort(key=lambda t: (t.status != "triggered", -(t.id or 0)))
    return rows


def delete_canary(session: Session, canary_id: int) -> bool:
    """Убрать приманку. Индикатор снимается с раздачи только если он больше
    никому не нужен: на одном пути может висеть несколько приманок (например
    разложенных по разным машинам), и удаление одной не должно ослеплять
    остальные."""
    token = session.get(CanaryToken, canary_id)
    if token is None:
        return False
    indicator_id = token.indicator_id
    session.delete(token)
    session.commit()
    if indicator_id is not None:
        others = session.exec(
            select(CanaryToken).where(CanaryToken.indicator_id == indicator_id).limit(1)
        ).first()
        if others is None:
            ind = session.get(ThreatIndicator, indicator_id)
            if ind is not None:
                session.delete(ind)
                session.commit()
    return True


def mark_triggered(
    session: Session,
    token: CanaryToken,
    *,
    machine_id: str | None,
    actor: str | None,
    when: datetime | None = None,
) -> CanaryToken:
    """Отметить первую сработку. Повторные обращения состояние не меняют —
    приманка срабатывает один раз, дальше это уже известный инцидент."""
    if token.status != "triggered":
        token.status = "triggered"
        token.triggered_at = when or datetime.now(UTC)
        token.triggered_machine_id = machine_id
        token.triggered_actor = actor
        session.add(token)
        session.commit()
        session.refresh(token)
    return token


# --- детект сработки ---------------------------------------------------------

RULE_ID = "canary.triggered"
# Приманка не накапливает риск и не имеет порога: обращение к ней уже означает
# целенаправленный поиск секретов, поэтому сразу критично.
SEVERITY = "critical"


def _signal_id_for(indicator_id: int) -> str:
    """Как выглядит сигнал приманки в событии агента.

    Формат задаёт indicator_override_service (``cred.read.store_<id>``);
    держим его здесь одной функцией, чтобы связь была явной и ломалась
    в одном месте, если формат когда-нибудь изменится.
    """
    return f"cred.read.store_{indicator_id}"


def tick(session: Session) -> dict[str, object]:
    """Найти обращения к приманкам и поднять тревогу.

    Пороги и окна намеренно отсутствуют: у приманки нет законных причин для
    обращения, поэтому первое же событие — инцидент.
    """
    import json

    from ccguard.server.db.models import FindingRecord, ToolUseEvent

    armed = list(
        session.exec(
            select(CanaryToken)
            .where(CanaryToken.status == "armed")
            .where(CanaryToken.indicator_id.is_not(None))  # type: ignore[attr-defined]
        )
    )
    if not armed:
        return {"canaries_checked": 0, "findings_emitted": 0, "errors": []}

    emitted = 0
    errors: list[str] = []
    for token in armed:
        try:
            needle = _signal_id_for(int(token.indicator_id or 0))
            stmt = select(ToolUseEvent).where(
                ToolUseEvent.signals_json.contains(needle)  # type: ignore[attr-defined]
            )
            # Приманка, привязанная к машине, срабатывает только на ней.
            if token.machine_id:
                stmt = stmt.where(ToolUseEvent.machine_id == token.machine_id)
            event = session.exec(stmt.order_by(ToolUseEvent.ts)).first()  # type: ignore[arg-type]
            if event is None:
                continue

            recipe = RECIPES.get(token.token_type)
            title = recipe.title if recipe else token.token_type
            payload = {
                "canary_id": token.id,
                "token_type": token.token_type,
                "file_path": token.file_path,
                "label": token.label,
                "actor_user": event.actor_user,
                "permission_mode": event.permission_mode,
                "tool_name": event.tool_name,
                "at": event.ts.isoformat(),
                "narrative": (
                    f"Обращение к приманке «{title}» ({token.file_path}). "
                    "Этот файл ничего не открывает и не нужен ни одному инструменту — "
                    "к нему обращаются только при целенаправленном поиске секретов. "
                    "Ложное срабатывание здесь невозможно."
                ),
                "recommendation": (
                    "Считай учётные данные на этой машине скомпрометированными: "
                    "разберись, что выполнялось рядом по времени, и ротируй ключи."
                ),
            }
            session.add(
                FindingRecord(
                    machine_id=event.machine_id,
                    inventory_id=None,
                    rule_id=RULE_ID,
                    severity=SEVERITY,
                    discovered_at=datetime.now(UTC),
                    payload_json=json.dumps(payload, ensure_ascii=False, allow_nan=False),
                )
            )
            session.commit()
            mark_triggered(
                session, token, machine_id=event.machine_id, actor=event.actor_user,
                when=event.ts,
            )
            emitted += 1
        except Exception as exc:  # noqa: BLE001 — изоляция границы намеренная
            try:
                session.rollback()
            except Exception:  # noqa: BLE001
                pass
            errors.append(f"canary {token.id}: {exc}")
            log.warning("canary tick error: %s", errors[-1])
    return {"canaries_checked": len(armed), "findings_emitted": emitted, "errors": errors}
