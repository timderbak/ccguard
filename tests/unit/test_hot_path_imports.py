"""Горячий путь проверки не должен тянуть тяжёлые зависимости.

Проверка встроена в каждый вызов инструмента: всё, что она тратит на старте,
разработчик ждёт лично, десятки раз в час. Импорт на уровне модуля — самая
незаметная утечка этого бюджета: библиотека может не использоваться ни разу за
запуск, но платить за неё приходится всегда.

Конкретный случай, ради которого написан тест: ``httpx`` (нужен только для
необязательной проверки моделью, которая в большинстве установок выключена)
импортировался на уровне модуля и стоил около 95 мс — почти весь бюджет
проверки ещё до её начала. Комментарий рядом при этом утверждал, что стоимость
импорта нулевая: ленивым было создание клиента, а не сам импорт.
"""
from __future__ import annotations

import subprocess
import sys

# Библиотеки, которых не должно быть в памяти после импорта горячего пути.
# Каждая тянет за собой ещё несколько (httpx тянет rich и click), поэтому
# проверяются именно они, а не полный список.
_FORBIDDEN = ("httpx", "rich", "click")


def _modules_after_import(module: str) -> set[str]:
    """Список загруженных модулей после импорта — в отдельном процессе.

    В общем процессе тест был бы бесполезен: любой другой тест, успевший
    импортировать httpx раньше, сделал бы проверку всегда зелёной.
    """
    code = (
        "import sys, json;"
        f"__import__({module!r});"
        "print(json.dumps(sorted(sys.modules)))"
    )
    out = subprocess.run(  # noqa: S603 — свой же интерпретатор
        [sys.executable, "-c", code], capture_output=True, text=True, check=True,
    )
    import json

    return set(json.loads(out.stdout))


def test_pi_engine_does_not_import_httpx():
    loaded = _modules_after_import("ccguard.agent.prompt_injection_engine")
    present = [m for m in _FORBIDDEN if m in loaded]
    assert not present, (
        f"движок проверки текста тянет {present} на импорте — "
        "это десятки миллисекунд в каждом вызове инструмента"
    )


def test_enforce_does_not_import_httpx():
    loaded = _modules_after_import("ccguard.agent.enforce")
    present = [m for m in _FORBIDDEN if m in loaded]
    assert not present, (
        f"проверка перед вызовом инструмента тянет {present} на импорте — "
        "это десятки миллисекунд, которые разработчик ждёт лично"
    )


def test_lazy_import_still_lets_llama_guard_work():
    # Ленивый импорт не должен превратиться в неработающую ветку: если бы
    # httpx не импортировался и внутри функции, проверка моделью падала бы
    # только у тех, кто её включил, — то есть у самых внимательных.
    code = (
        "from ccguard.agent import prompt_injection_engine as e;"
        "import httpx;"  # то же имя, что использует ленивая ветка
        "print('ok' if hasattr(e, '_lg_client') else 'no')"
    )
    out = subprocess.run(  # noqa: S603 — свой же интерпретатор
        [sys.executable, "-c", code], capture_output=True, text=True, check=True,
    )
    assert out.stdout.strip() == "ok"
