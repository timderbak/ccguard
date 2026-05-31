"""IP-as-host detector — поднимаем сигнал, когда вместо доменного имени
напрямую используется IP-адрес (включая обфусцированные формы).
"""
from __future__ import annotations

import pytest

from ccguard.agent.network_utils import detect_ip_as_host


@pytest.mark.parametrize(
    "host,expected",
    [
        ("192.168.0.1", True),
        ("8.8.8.8", True),
        ("127.0.0.1", True),
        # Обфусцированные формы IPv4:
        ("0x7f000001", True),   # hex 127.0.0.1
        ("2130706433", True),   # decimal 127.0.0.1
        # IPv6 в URL хост приходит без скобок (urlparse уже снял `[]`).
        ("::1", True),
        ("2001:db8::1", True),
        # Доменные имена — не IP.
        ("example.com", False),
        ("api.github.com", False),
        ("localhost", False),
        ("", False),
        # Не путаем строки с числами в имени домена.
        ("v2.example.com", False),
        ("123abc.example.com", False),
    ],
)
def test_detect_ip_as_host(host: str, expected: bool) -> None:
    assert detect_ip_as_host(host) is expected
