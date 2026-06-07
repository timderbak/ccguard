"""E2E gate.

The ``e2e`` suite needs a live stack (``docker compose up -d server``, agent
container, reachable URLs). In a plain ``uv run pytest`` / headless / CI-without-
docker run those tests can't connect and fail with ConnectError / missing
fixtures — noise, not product bugs (see docs/TEST_AUDIT.md).

So we skip every ``e2e``-marked test UNLESS ``CCGUARD_E2E=1`` is set. The tests
are preserved and run unchanged in the real e2e environment; they just stop
nagging everywhere else. Opt in with:

    CCGUARD_E2E=1 uv run pytest tests/e2e
"""
from __future__ import annotations

import os

import pytest

_E2E_ENABLED = os.environ.get("CCGUARD_E2E") == "1"
_SKIP_REASON = (
    "e2e: требует живого стека (docker compose up -d server); "
    "запускать с CCGUARD_E2E=1"
)


def pytest_collection_modifyitems(
    config: pytest.Config, items: list[pytest.Item]
) -> None:
    if _E2E_ENABLED:
        return
    skip = pytest.mark.skip(reason=_SKIP_REASON)
    for item in items:
        if "e2e" in item.keywords:
            item.add_marker(skip)
