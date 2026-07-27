"""ccguard egress-прокси — НАБЛЮДАЕМОСТЬ поверх enforce песочницы.

Сам запрет egress уже делает ВСТРОЕННЫЙ прокси песочницы Claude Code (allowlist
прошит в root-managed-settings, см. ``harden.build_managed_settings``). Этот
модуль добавляет то, чего встроенный прокси наружу не отдаёт: если оператор
направит ``sandbox.network.httpProxyPort`` на локальный ccguard-прокси, тот
пропускает/блокирует по тому же allowlist И **логирует каждую попытку**
исходящего соединения, включая заблокированные — «куда агент пытался ходить».

Философия — как у :mod:`ccguard.agent.harden`: чистое ТЕСТИРУЕМОЕ ядро (политика
+ разбор CONNECT + решение по соединению с инъектируемым upstream/событием),
а РЕАЛЬНАЯ маршрутизация песочницы на этот порт — field-test на эндпоинте.
По умолчанию порт в managed-settings НЕ прописывается: указать несуществующий
прокси значило бы обрубить агенту весь egress.

Enforce на HTTPS работает БЕЗ терминации TLS: хост виден в открытом виде в строке
``CONNECT host:443`` — по нему и решаем. Терминация TLS (инспекция полезной
нагрузки + маскирование кредов) требует CA-сертификата в песочнице и остаётся
отдельным field-test.
"""
from __future__ import annotations

import contextlib
import socket
import threading
from collections.abc import Callable
from dataclasses import dataclass

# Домен, без которого Claude Code не работает: пускаем всегда (как в harden-lock).
_REQUIRED_DOMAIN = "api.anthropic.com"
_MAX_HEADER_BYTES = 8192


class EgressPolicy:
    """Решение «пускать ли исходящее соединение на host» по allowlist доменов.

    api.anthropic.com разрешён всегда. Домен матчится точно или как родитель
    поддомена (``api.example.com`` разрешает ``x.api.example.com``, но не
    ``evilexample.com``). Пустой allowlist = только обязательный домен.
    """

    def __init__(self, allowlist: list[str] | None) -> None:
        domains: set[str] = {_REQUIRED_DOMAIN}
        for raw in allowlist or []:
            d = raw.strip().strip("/").lower()
            if d:
                domains.add(d)
        self.domains = domains

    def allows(self, host: str) -> bool:
        h = (host or "").strip().lower().rstrip(".")
        if not h:
            return False
        return any(h == d or h.endswith("." + d) for d in self.domains)


def policy_from_managed_settings(data: object) -> EgressPolicy:
    """Собрать политику из ``sandbox.network.allowedDomains`` managed-settings.

    Прокси enforce'ит ТОТ ЖЕ список, что и встроенная песочница, — единый
    источник правды. Нет блока/ключа → пустой allowlist (только обязательный
    домен). Пустой allowlist здесь означает «сужения нет» на стороне песочницы,
    но прокси всё равно логирует попытки — в этом и смысл наблюдаемости.
    """
    allow: list[str] = []
    if isinstance(data, dict):
        net = (data.get("sandbox") or {}).get("network") if isinstance(data.get("sandbox"), dict) else None
        if isinstance(net, dict) and isinstance(net.get("allowedDomains"), list):
            allow = [str(d) for d in net["allowedDomains"]]
    return EgressPolicy(allow)


@dataclass
class EgressEvent:
    """Одна попытка исходящего соединения (для лога/отчёта)."""

    host: str
    port: int
    allowed: bool


def parse_connect(request_line: str) -> tuple[str, int] | None:
    """``'CONNECT host:443 HTTP/1.1'`` → ``('host', 443)``. None, если не CONNECT.

    Порт по умолчанию 443 (HTTPS-туннель). Хост нормализуем позже в политике.
    """
    parts = request_line.split()
    if len(parts) < 2 or parts[0].upper() != "CONNECT":
        return None
    target = parts[1]
    if ":" in target:
        host, _, port_s = target.rpartition(":")
        try:
            port = int(port_s)
        except ValueError:
            return None
    else:
        host, port = target, 443
    if not host:
        return None
    return host, port


def _read_headers(conn: object) -> str:
    """Прочитать блок заголовков до пустой строки; вернуть ПЕРВУЮ строку запроса.

    CONNECT-клиент шлёт ``CONNECT ...\\r\\nHost: ...\\r\\n\\r\\n`` и ждёт ответа
    перед TLS, поэтому вычитываем весь блок, чтобы туннель начался с чистого
    места.
    """
    buf = b""
    while b"\r\n\r\n" not in buf and len(buf) < _MAX_HEADER_BYTES:
        chunk = conn.recv(1024)  # type: ignore[attr-defined]
        if not chunk:
            break
        buf += chunk
    return buf.split(b"\r\n", 1)[0].decode("latin-1", "replace")


def _default_dial(host: str, port: int, timeout: float = 10.0) -> socket.socket:
    return socket.create_connection((host, port), timeout=timeout)


def _tunnel(a: object, b: object) -> None:
    """Двунаправленно перекачивать байты между сокетами до закрытия любой стороны."""
    def pipe(src: object, dst: object) -> None:
        try:
            while True:
                data = src.recv(65536)  # type: ignore[attr-defined]
                if not data:
                    break
                dst.sendall(data)  # type: ignore[attr-defined]
        except OSError:
            pass
        finally:
            for s in (src, dst):
                with contextlib.suppress(OSError):
                    s.close()  # type: ignore[attr-defined]

    t1 = threading.Thread(target=pipe, args=(a, b), daemon=True)
    t2 = threading.Thread(target=pipe, args=(b, a), daemon=True)
    t1.start()
    t2.start()
    t1.join()
    t2.join()


def handle_connection(
    conn: object,
    policy: EgressPolicy,
    on_event: Callable[[EgressEvent], None] | None = None,
    *,
    dial: Callable[[str, int], object] | None = None,
) -> None:
    """Обработать одно клиентское соединение (CONNECT-прокси).

    Чистое ядро: ``conn`` и ``dial`` инъектируемы, поэтому тестируется без
    реальной сети. Разрешено → 200 и туннель к upstream; запрещено → 403 и
    соединение закрывается; в обоих случаях зовётся ``on_event``.
    """
    dial = dial or _default_dial
    try:
        first_line = _read_headers(conn)
    except OSError:
        return
    parsed = parse_connect(first_line)
    if parsed is None:
        # ccguard-прокси обслуживает только CONNECT (HTTPS-туннель песочницы).
        conn.sendall(b"HTTP/1.1 405 Method Not Allowed\r\n\r\n")  # type: ignore[attr-defined]
        _close(conn)
        return
    host, port = parsed
    allowed = policy.allows(host)
    if on_event is not None:
        on_event(EgressEvent(host=host, port=port, allowed=allowed))
    if not allowed:
        conn.sendall(  # type: ignore[attr-defined]
            b"HTTP/1.1 403 Forbidden\r\nX-Ccguard: egress-denied\r\n\r\n"
        )
        _close(conn)
        return
    try:
        upstream = dial(host, port)
    except OSError:
        conn.sendall(b"HTTP/1.1 502 Bad Gateway\r\n\r\n")  # type: ignore[attr-defined]
        _close(conn)
        return
    conn.sendall(b"HTTP/1.1 200 Connection established\r\n\r\n")  # type: ignore[attr-defined]
    _tunnel(conn, upstream)


def _close(conn: object) -> None:
    with contextlib.suppress(OSError):
        conn.close()  # type: ignore[attr-defined]


def serve(
    port: int,
    policy: EgressPolicy,
    on_event: Callable[[EgressEvent], None] | None = None,
    *,
    host: str = "127.0.0.1",
) -> None:  # pragma: no cover — тонкий accept-цикл; ядро покрыто handle_connection
    """Запустить прокси (блокирующий accept-цикл). FIELD-TEST: реальная
    маршрутизация песочницы на этот порт проверяется на эндпоинте — юнит-тесты
    покрывают ``handle_connection``/``EgressPolicy``/``parse_connect``, а не сам
    цикл. Слушаем только loopback: прокси для агента на ЭТОЙ машине, не сетевой
    сервис."""
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind((host, port))
    srv.listen(64)
    while True:
        conn, _ = srv.accept()
        threading.Thread(
            target=handle_connection, args=(conn, policy, on_event), daemon=True
        ).start()
