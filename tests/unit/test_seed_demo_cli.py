"""Команда наполнения демо-данными: она была сломана в трёх местах сразу.

Ошибки нашлись только при живом запуске, и это показательно: команду написали,
покрыли соседний код, но ни разу не выполнили целиком. Все три ломали её
полностью, а не по краям:

1. модуль симулятора загружался мимо ``sys.modules``, и ``@dataclass`` падал на
   разборе отложенных аннотаций — команда не доживала до отправки данных;
2. адрес сервера передавался флагом ``--server-url``, а симулятор понимает
   ``--server`` — падение на разборе аргументов;
3. события отправлялись на машину, не заведённую в реестре: приём событий и
   регистрация машины — разные потоки. Страница машины отдавала 404, а вся
   защитная логика эту машину не видела, потому что перебирает реестр.

Поэтому тесты здесь проверяют не внутренности, а стыки: загружается ли модуль
тем же способом, каким его грузит команда, и понимает ли симулятор ровно те
аргументы, которые команда ему передаёт.
"""
from __future__ import annotations

import importlib.util
import inspect
import sys
from pathlib import Path

from ccguard.agent import cli as agent_cli

_SIM_PATH = Path(__file__).resolve().parents[2] / "scripts" / "attack_simulator.py"


def _load_simulator():
    """Загрузить симулятор ТЕМ ЖЕ способом, что и команда."""
    spec = importlib.util.spec_from_file_location("_ccguard_attack_sim_test", _SIM_PATH)
    assert spec and spec.loader
    mod = importlib.util.module_from_spec(spec)
    # Регистрация обязательна: @dataclass разбирает отложенные аннотации через
    # sys.modules[cls.__module__]. Ровно эта строка и была пропущена.
    sys.modules[spec.name] = mod
    try:
        spec.loader.exec_module(mod)
    finally:
        sys.modules.pop(spec.name, None)
    return mod


def test_simulator_loads_the_way_the_command_loads_it():
    mod = _load_simulator()
    assert hasattr(mod, "main")
    assert hasattr(mod, "SCENARIOS")


def test_command_registers_the_module_before_executing_it():
    # Регрессия на пункт 1: без этой строки команда падала с невнятным
    # «NoneType has no attribute __dict__» ещё до отправки данных.
    src = inspect.getsource(agent_cli.seed_demo)
    reg = src.index("_sys.modules[spec.name] = mod")
    exec_ = src.index("spec.loader.exec_module(mod)")
    assert reg < exec_, "модуль должен попасть в sys.modules ДО выполнения"


def test_command_passes_arguments_the_simulator_understands():
    # Регрессия на пункт 2: имена флагов у двух сторон разъехались, и команда
    # падала на разборе аргументов. Сверяем по факту — разбираем то, что
    # команда действительно передаёт, настоящим парсером симулятора.
    src = inspect.getsource(agent_cli.seed_demo)
    start = src.index("_sys.argv = [")
    flags = [
        line.strip().strip(",").split(",")[0].strip().strip('"')
        for line in src[start:src.index("]", start)].splitlines()
        if line.strip().startswith('"--')
    ]
    assert flags, "не нашли передаваемые флаги — тест устарел, поправь разбор"

    mod = _load_simulator()
    # Значения подставляем осмысленные: у --scenario ограниченный набор, и
    # заглушка провалилась бы по значению, а проверяем мы имена флагов.
    values = {"--scenario": next(iter(mod.SCENARIOS))}
    argv = []
    for f in flags:
        argv += [f, values.get(f, "x")]
    # Парсер симулятора обязан принять этот набор без ошибок. Незнакомый флаг
    # приводит к SystemExit — то есть к падению команды у пользователя.
    parser_ok = True
    old = sys.argv
    try:
        sys.argv = [str(_SIM_PATH), *argv, "--dry-run"]
        try:
            mod.main()
        except SystemExit as e:
            parser_ok = e.code in (0, None)
        except Exception:  # noqa: BLE001 — падение НЕ на аргументах нам не важно
            parser_ok = True
    finally:
        sys.argv = old
    assert parser_ok, f"симулятор не понимает флаги, которые ему передаёт команда: {flags}"


def test_registration_failure_does_not_kill_the_command(capsys):
    # Регрессия на пункт 3 и на его поведение при отказе: сервер может быть не
    # поднят, и это не повод терять события. Причина должна быть названа, а не
    # проглочена.
    agent_cli._seed_demo_register_machine(
        # Порт заведомо закрыт — быстрый отказ соединения, без сети наружу.
        server_url="http://127.0.0.1:1", token="t", machine="m-x",
    )
    err = capsys.readouterr().err
    assert "зарегистрировать не удалось" in err


def test_command_registers_machine_before_sending_events():
    # Порядок важен: события, пришедшие раньше регистрации, лягут на машину,
    # которой для сервера ещё не существует.
    src = inspect.getsource(agent_cli.seed_demo)
    assert (
        src.index("_seed_demo_register_machine")
        < src.index("spec.loader.exec_module(mod)")
    )
