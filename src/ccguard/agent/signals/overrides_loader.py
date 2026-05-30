"""Load server-pushed signal overrides from the agent's cached policy file.

E4 hot-path glue. The hook subprocess calls :func:`load_overrides` once at
the start of each event before invoking ``extract_signals``. YAML parse of
a small policy file is ~1-2 ms — well inside the <20 ms hook budget.

Fail-open: any error (missing file, malformed YAML, missing/invalid section)
returns an empty list so the agent silently degrades to baked-CATALOG-only.
"""
from __future__ import annotations

import logging
from pathlib import Path
from typing import Any

import yaml

log = logging.getLogger(__name__)

_REQUIRED_KEYS = ("id", "attack_technique", "pattern", "description")


def load_overrides(policy_cache_path: Path) -> list[dict[str, Any]]:
    """Return the validated ``signal_overrides`` list, or ``[]`` on any error."""
    try:
        text = policy_cache_path.read_text()
    except (OSError, UnicodeDecodeError):
        return []
    try:
        data = yaml.safe_load(text)
    except yaml.YAMLError:
        log.debug("policy cache YAML malformed; ignoring overrides")
        return []
    if not isinstance(data, dict):
        return []
    raw = data.get("signal_overrides")
    if not isinstance(raw, list):
        return []
    out: list[dict[str, Any]] = []
    for entry in raw:
        if not isinstance(entry, dict):
            continue
        if not all(isinstance(entry.get(k), str) and entry[k] for k in _REQUIRED_KEYS):
            continue
        out.append({k: entry[k] for k in _REQUIRED_KEYS})
    return out
