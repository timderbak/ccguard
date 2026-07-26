"""Чтение политики на горячем пути enforce — без pydantic.

Политика в кэше уже нормализована: сервер отдаёт её как ``model_dump`` полной
:class:`~ccguard.schemas.policy.Policy`, то есть со ВСЕМИ дефолтами, включая
защитные списки (``commands.always_deny``, ``commands.dangerous_patterns``).
Поэтому здесь их НЕ нужно дублировать — мы читаем готовое, а не достраиваем.

Зачем вообще: импорт pydantic и построение модели Policy на горячем пути стоят
~200мс — вдвое больше всего бюджета проверки (100мс). ``yaml.safe_load`` +
тонкая обёртка с атрибут-доступом дают те же значения полей за единицы мс.

Корректность держится на трёх опорах, а не на честном слове:
1. Кэш нормализован сервером (model_dump) — дефолты уже проставлены pydantic.
2. Тест эквивалентности (``test_fast_policy_equivalence``) сверяет КАЖДОЕ поле,
   которое читает enforce, между FastPolicy и настоящей pydantic-Policy на
   примере и на минимальной политике — расхождение дефолта падает тестом.
3. Ярус hard-deny в enforce НЕ зависит от политики вообще: даже если кэш пуст
   или битый, заведомое зло (reverse shell, отключение ccguard) режется всё
   равно. FastPolicy не может открыть эту дыру, потому что её там нет.
"""
from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml


class _Node:
    """Атрибут-доступ к разобранному словарю политики.

    ``pol.denylist_patterns`` вместо ``pol["denylist_patterns"]`` — чтобы код
    enforce, писавшийся под pydantic-модель, не переписывать. Вложенные словари
    оборачиваются рекурсивно, списки — поэлементно (правило видно как
    ``rule.id`` / ``rule.pattern``).

    Отсутствующий ключ → ``None``. На нормализованном кэше (см. модульный
    докстринг) отсутствующих полей не бывает; ``None`` — страховка от битого
    кэша, а не рабочий путь. Списочные поля на нормализованном кэше всегда
    присутствуют реальными списками, поэтому итерации enforce безопасны.
    """

    __slots__ = ("_d",)

    def __init__(self, data: dict[str, Any]) -> None:
        self._d = data

    def __getattr__(self, name: str) -> Any:
        try:
            return _wrap(self._d[name])
        except KeyError:
            return None

    def __contains__(self, name: str) -> bool:
        return name in self._d

    def get(self, name: str, default: Any = None) -> Any:
        if name in self._d:
            return _wrap(self._d[name])
        return default


def _wrap(value: Any) -> Any:
    if isinstance(value, dict):
        return _Node(value)
    if isinstance(value, list):
        return [_wrap(v) for v in value]
    return value


class FastPolicy(_Node):
    """Корень политики. Те же атрибуты, что читает enforce у pydantic-Policy."""


def parse_fast_policy(text: str) -> FastPolicy | None:
    """Разобрать текст кэша политики (YAML/JSON — YAML их надмножество)."""
    try:
        data = yaml.safe_load(text)
    except Exception:  # noqa: BLE001 — битый кэш = нет политики (fail к hard-deny)
        return None
    if not isinstance(data, dict):
        return None
    return FastPolicy(data)


def load_fast_policy(path: str) -> FastPolicy | None:
    """Прочитать политику из кэша без pydantic. None — если файла нет/битый."""
    p = Path(path)
    try:
        if not p.exists():
            return None
        return parse_fast_policy(p.read_text())
    except OSError:
        return None
