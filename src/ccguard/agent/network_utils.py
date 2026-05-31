"""Network utilities for enforce: IP-as-host detection and host classification.

Выделено в отдельный модуль, чтобы:

* `_decide_web` (WebFetch/WebSearch) и `_decide_bash` (curl/wget) могли
  переиспользовать общий хелпер `check_network_target()`.
* Логику IP-as-host (включая обфусцированные формы) можно было покрыть
  отдельным юнит-тестом без поднятия Policy.
"""
from __future__ import annotations

import ipaddress
import re

# Plain dotted IPv4. Hex/decimal IPv4 — отдельные ветки в detect_ip_as_host
# (ipaddress.ip_address не парсит `0x...` / `2130706433` напрямую).
_IPV4_DOTTED = re.compile(r"^(\d{1,3}\.){3}\d{1,3}$")
_HEX_INT = re.compile(r"^0x[0-9a-fA-F]+$")
_DECIMAL_INT = re.compile(r"^\d+$")


def detect_ip_as_host(hostname: str) -> bool:
    """True если ``hostname`` — IP-адрес (включая обфусцированные формы).

    Покрывает:
    * Plain IPv4 (``192.168.0.1``)
    * Hex IPv4 (``0x7f000001``)
    * Decimal IPv4 (``2130706433`` == 127.0.0.1)
    * IPv6 (``::1``, ``2001:db8::1``) — без квадратных скобок (urlparse их снимает)

    Пустая строка — False.
    """
    if not hostname:
        return False
    # 1. Plain IPv4.
    if _IPV4_DOTTED.match(hostname):
        try:
            ipaddress.IPv4Address(hostname)
            return True
        except (ipaddress.AddressValueError, ValueError):
            return False
    # 2. Hex / decimal integer формы IPv4. ipaddress.IPv4Address принимает int.
    if _HEX_INT.match(hostname):
        try:
            n = int(hostname, 16)
            ipaddress.IPv4Address(n)
            return True
        except (ValueError, ipaddress.AddressValueError):
            return False
    if _DECIMAL_INT.match(hostname):
        try:
            n = int(hostname)
            if 0 <= n <= 0xFFFFFFFF:
                ipaddress.IPv4Address(n)
                return True
        except (ValueError, ipaddress.AddressValueError):
            return False
    # 3. IPv6 — пробуем как есть.
    if ":" in hostname:
        try:
            ipaddress.IPv6Address(hostname)
            return True
        except (ipaddress.AddressValueError, ValueError):
            return False
    return False


def is_private_ip(hostname: str) -> bool:
    """True если hostname — IP в private/loopback диапазоне.

    Возвращает False для не-IP (доменных имён). Использует
    ``ipaddress.ip_address(...).is_private`` для IPv4, что покрывает
    10/8, 172.16/12, 192.168/16, 127/8 (loopback тоже private в смысле
    is_private).
    """
    if not hostname:
        return False
    # plain IPv4
    if _IPV4_DOTTED.match(hostname):
        try:
            addr = ipaddress.IPv4Address(hostname)
            return bool(addr.is_private or addr.is_loopback)
        except (ipaddress.AddressValueError, ValueError):
            return False
    return False
