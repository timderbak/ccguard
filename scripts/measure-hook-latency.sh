#!/usr/bin/env bash
# Замер задержки проверки перед вызовом инструмента.
#
# Эта цифра — не украшение. Проверка встроена в каждый вызов инструмента, и
# всё, что она тратит, разработчик ждёт лично, десятки раз в час. Поэтому её
# нужно уметь измерять одной командой, а не оценивать по памяти: заявленная
# в документации цифра расходится с фактической ровно до тех пор, пока её
# никто не проверяет.
#
#   ./scripts/measure-hook-latency.sh                    # текущий путь (venv)
#   ./scripts/measure-hook-latency.sh путь/к/бинарнику   # собранный вариант
#
# Замеряется ПОЛНОЕ время вызова: старт процесса, импорты, разбор политики,
# решение. Именно его видит пользователь — измерять одну лишь функцию решения
# бессмысленно, стартовать процесс всё равно приходится каждый раз.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
RUNS="${RUNS:-10}"
BUDGET_MS="${BUDGET_MS:-100}"
TARGET="${1:-}"

# Безобидный вызов, который должен быть разрешён: мерить надо обычный путь,
# а не редкую ветку с блокировкой.
PAYLOAD='{"tool_name":"Bash","tool_input":{"command":"echo hello"}}'

run_once() {
    if [ -n "$TARGET" ]; then
        echo "$PAYLOAD" | "$TARGET" >/dev/null 2>&1 || true
    else
        echo "$PAYLOAD" | "${PYTHON:-$ROOT/.venv/bin/python}" \
            -m ccguard.agent.enforce_main >/dev/null 2>&1 || true
    fi
}

# Один холостой прогон: первый запуск прогревает кэш файловой системы, и
# включать его в среднее — значит мерить состояние диска, а не программу.
run_once

START=$(date +%s%N)
for _ in $(seq 1 "$RUNS"); do run_once; done
END=$(date +%s%N)

AVG=$(( (END - START) / RUNS / 1000000 ))
echo "проверяемый путь: ${TARGET:-python -m ccguard.agent.enforce_main}"
echo "прогонов: $RUNS"
echo "средняя задержка: ${AVG} мс (бюджет — ${BUDGET_MS} мс)"

if [ "$AVG" -gt "$BUDGET_MS" ]; then
    echo "БЮДЖЕТ ПРЕВЫШЕН на $(( AVG - BUDGET_MS )) мс" >&2
    exit 1
fi
