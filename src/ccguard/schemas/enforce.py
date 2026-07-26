"""Схемы hook-протокола enforce.

Сами типы (EnforceHookInput, EnforceDecision) вынесены в
:mod:`ccguard.agent.hot_types` как обычные dataclass'ы БЕЗ pydantic: они лежат
на горячем пути проверки, где импорт pydantic (~90мс) и построение моделей
(~110мс) вдвое превышали весь бюджет задержки (100мс). Здесь оставлен реэкспорт,
чтобы прежние импорты ``from ccguard.schemas import EnforceDecision`` (сервер,
тесты — не горячий путь) продолжали работать без изменений.
"""
from __future__ import annotations

from ccguard.agent.hot_types import EnforceDecision, EnforceHookInput

__all__ = ["EnforceDecision", "EnforceHookInput"]
