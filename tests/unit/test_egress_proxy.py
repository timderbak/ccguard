"""ccguard egress-прокси: чистое ядро (политика + разбор CONNECT + решение).

Реальный accept-цикл (serve) — field-test на эндпоинте; здесь через фейковые
сокеты покрыто ядро: кого пускаем, как отвечаем на запрет, что логируем.
"""
from __future__ import annotations

from ccguard.agent.egress_proxy import (
    EgressEvent,
    EgressPolicy,
    handle_connection,
    parse_connect,
    policy_from_managed_settings,
)


def test_policy_from_managed_settings_reads_sandbox_allowlist():
    data = {"sandbox": {"network": {"allowedDomains": ["pypi.org", "github.com"]}}}
    p = policy_from_managed_settings(data)
    assert p.allows("pypi.org") and p.allows("github.com")
    assert p.allows("api.anthropic.com")  # обязательный всегда
    assert not p.allows("evil.com")


def test_policy_from_managed_settings_handles_missing_blocks():
    # Нет sandbox/network/allowedDomains → пустой allowlist (только обязательный).
    for data in ({}, {"sandbox": {}}, {"sandbox": {"network": {}}}, {"sandbox": "x"}):
        p = policy_from_managed_settings(data)
        assert p.allows("api.anthropic.com")
        assert not p.allows("pypi.org")


# --- EgressPolicy ----------------------------------------------------------


def test_policy_always_allows_anthropic_api():
    assert EgressPolicy([]).allows("api.anthropic.com") is True


def test_policy_allowlist_and_subdomains():
    p = EgressPolicy(["pypi.org", "github.com"])
    assert p.allows("pypi.org") is True
    assert p.allows("files.pythonhosted.org") is False   # нет в списке
    assert p.allows("codeload.github.com") is True         # поддомен github.com
    assert p.allows("evilgithub.com") is False             # не поддомен, похожее имя
    assert p.allows("") is False


def test_policy_normalizes_case_and_trailing_dot():
    p = EgressPolicy(["Pypi.org/"])
    assert p.allows("PYPI.ORG.") is True


# --- parse_connect ---------------------------------------------------------


def test_parse_connect_host_port():
    assert parse_connect("CONNECT evil.com:443 HTTP/1.1") == ("evil.com", 443)
    assert parse_connect("CONNECT h.io:8443 HTTP/1.1") == ("h.io", 8443)
    assert parse_connect("connect h.io HTTP/1.1") == ("h.io", 443)  # порт по умолчанию


def test_parse_connect_rejects_non_connect():
    assert parse_connect("GET http://x/ HTTP/1.1") is None
    assert parse_connect("CONNECT") is None
    assert parse_connect("CONNECT h:notaport HTTP/1.1") is None


# --- handle_connection (фейковые сокеты) -----------------------------------


class _FakeConn:
    def __init__(self, data: bytes) -> None:
        self._in = data
        self.sent = b""
        self.closed = False

    def recv(self, n: int) -> bytes:
        chunk, self._in = self._in[:n], self._in[n:]
        return chunk

    def sendall(self, b: bytes) -> None:
        self.sent += b

    def close(self) -> None:
        self.closed = True


def test_denied_host_gets_403_and_event():
    events: list[EgressEvent] = []
    conn = _FakeConn(b"CONNECT evil.com:443 HTTP/1.1\r\nHost: evil.com\r\n\r\n")
    dialed: list = []
    handle_connection(
        conn, EgressPolicy(["pypi.org"]), events.append,
        dial=lambda h, p: dialed.append((h, p)),  # не должен вызваться
    )
    assert conn.sent.startswith(b"HTTP/1.1 403")
    assert b"egress-denied" in conn.sent
    assert conn.closed is True
    assert dialed == []                       # запрещённый upstream не набирался
    assert events == [EgressEvent(host="evil.com", port=443, allowed=False)]


def test_allowed_host_gets_200_and_dials_upstream():
    events: list[EgressEvent] = []
    conn = _FakeConn(b"CONNECT pypi.org:443 HTTP/1.1\r\n\r\n")

    class _FakeUpstream:
        def recv(self, n: int) -> bytes:
            return b""  # сразу EOF → туннель мгновенно завершится
        def sendall(self, b: bytes) -> None:
            pass
        def close(self) -> None:
            pass

    dialed: list = []

    def _dial(h: str, p: int) -> _FakeUpstream:
        dialed.append((h, p))
        return _FakeUpstream()

    handle_connection(conn, EgressPolicy(["pypi.org"]), events.append, dial=_dial)
    assert b"HTTP/1.1 200" in conn.sent
    assert dialed == [("pypi.org", 443)]
    assert events == [EgressEvent(host="pypi.org", port=443, allowed=True)]


def test_non_connect_method_rejected():
    conn = _FakeConn(b"GET http://x/ HTTP/1.1\r\n\r\n")
    handle_connection(conn, EgressPolicy([]), None, dial=lambda h, p: None)
    assert conn.sent.startswith(b"HTTP/1.1 405")
    assert conn.closed is True
