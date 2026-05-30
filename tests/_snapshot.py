"""Tiny in-house snapshot tester — no new dependency.

Usage in a test:

    from tests._snapshot import assert_snapshot

    def test_machine_detail_renders(client, ...):
        r = client.get("/machines/m-foo", cookies=...)
        assert_snapshot("machine_detail/m-foo.html", r.text)

To regenerate snapshots after an intentional UI change::

    CCGUARD_UPDATE_SNAPSHOTS=1 uv run pytest tests/integration/test_render_snapshots.py

Snapshots live under ``tests/_snapshots/``. The helper normalizes dynamic
content (CSRF tokens, ISO timestamps, hex IDs) so the comparison stays
deterministic across runs without coupling to test fixtures.

Why this is better than ``assert 'foo' in body``:
* a change in the surrounding markup is visible as one diff in CI
* an intentional redesign is a one-command snapshot regen
* you stop adding 5 ``assert "x" in body`` lines per feature
"""
from __future__ import annotations

import difflib
import os
import re
from pathlib import Path

_SNAPSHOTS_DIR = Path(__file__).parent / "_snapshots"
_UPDATE_ENV = "CCGUARD_UPDATE_SNAPSHOTS"

# Normalizers — order matters; specific before general.
_NORMALIZERS: tuple[tuple[re.Pattern[str], str], ...] = (
    # CSRF tokens — itsdangerous format ``<payload>.<timestamp>.<sig>`` with
    # base64-url chars + dots. Match must run BEFORE the 64-hex normalizer.
    (re.compile(r'name="csrf_token"\s+value="[A-Za-z0-9_\-\.]+"'),
     'name="csrf_token" value="<CSRF>"'),
    # ISO 8601 datetimes (with or without timezone).
    (re.compile(r'\d{4}-\d{2}-\d{2}T\d{2}:\d{2}(:\d{2}(\.\d+)?)?(?:[+-]\d{2}:?\d{2}|Z)?'),
     '<ISO_TS>'),
    # Date strings YYYY-MM-DD.
    (re.compile(r'\b\d{4}-\d{2}-\d{2}\b'),
     '<DATE>'),
    # 64-hex digests (file hashes etc.).
    (re.compile(r'\b[0-9a-f]{64}\b'), '<HASH64>'),
    # 16-hex fingerprints.
    (re.compile(r'\b[0-9a-f]{16}\b'), '<HASH16>'),
)


def _normalize(text: str) -> str:
    for pattern, repl in _NORMALIZERS:
        text = pattern.sub(repl, text)
    return text


def assert_snapshot(name: str, actual: str) -> None:
    """Compare ``actual`` against the on-disk snapshot at
    ``tests/_snapshots/<name>``. Creates the snapshot on first run."""
    snap_path = _SNAPSHOTS_DIR / name
    snap_path.parent.mkdir(parents=True, exist_ok=True)
    actual_n = _normalize(actual)

    if os.environ.get(_UPDATE_ENV) == "1" or not snap_path.exists():
        snap_path.write_text(actual_n, encoding="utf-8")
        if not snap_path.exists():
            return
        # Update mode — pass the assertion.
        return

    expected = snap_path.read_text(encoding="utf-8")
    if actual_n == expected:
        return

    diff = "\n".join(
        difflib.unified_diff(
            expected.splitlines(),
            actual_n.splitlines(),
            fromfile=f"snapshot:{name}",
            tofile="actual",
            lineterm="",
            n=2,
        )
    )
    raise AssertionError(
        f"Snapshot {name} mismatch. To accept, rerun with "
        f"{_UPDATE_ENV}=1.\n{diff[:4000]}"
    )
