"""Convert browser form data → Policy YAML text (validated against schema)."""

from __future__ import annotations

from copy import deepcopy
from datetime import UTC, datetime
from typing import Any, Mapping

import yaml

from ccguard.schemas import Policy


def _csv_to_list(raw: str) -> list[str]:
    return [s.strip() for s in raw.split(",") if s.strip()]


def _lines_to_list(raw: str) -> list[str]:
    return [s.strip() for s in raw.splitlines() if s.strip()]


def _checkbox(raw: str) -> bool:
    return raw == "1"


def _section(form: Mapping[str, str], prefix: str, fields: dict[str, str]) -> dict[str, Any]:
    """Build a dict for one policy section.

    `fields` is {form_field: kind}, kind ∈ {"csv", "lines", "bool", "str"}.
    """
    out: dict[str, Any] = {}
    for field, kind in fields.items():
        raw = form.get(f"{prefix}.{field}", "")
        if kind == "csv":
            out[field] = _csv_to_list(raw)
        elif kind == "lines":
            out[field] = _lines_to_list(raw)
        elif kind == "bool":
            out[field] = _checkbox(raw)
        else:
            out[field] = raw
    return out


_SECTIONS: dict[str, dict[str, str]] = {
    "mcp_servers": {
        "severity": "str",
        "allowlist_names": "csv",
        "denylist_names": "csv",
        "allowlist_url_patterns": "csv",
        "denylist_url_patterns": "csv",
        "deny_all_unknown": "bool",
    },
    "network": {
        "severity": "str",
        "allowlist_hosts": "csv",
        "denylist_hosts": "csv",
        "deny_all_unknown": "bool",
    },
    "commands": {
        "severity": "str",
        "denylist_patterns": "lines",
        "allowlist_patterns": "lines",
    },
    "skills": {
        "severity": "str",
        "allowlist_names": "csv",
        "trusted_dir_hashes": "lines",
        "deny_all_unknown": "bool",
    },
    "hooks": {
        "severity": "str",
        "allowlist_commands": "lines",
        "deny_unknown": "bool",
    },
    "agents": {
        "severity": "str",
        "allowlist_names": "csv",
        "denylist_names": "csv",
        "denylist_tools": "csv",
        "trusted_file_hashes": "lines",
        "deny_all_unknown": "bool",
    },
    "env": {
        "severity": "str",
        "denylist_patterns": "lines",
        "allowlist_names": "csv",
    },
}


def form_to_yaml(
    form: Mapping[str, str],
    *,
    current_revision: int,
    baseline: dict | None = None,
) -> str:
    """Serialize form data into Policy YAML. Validates via Policy.model_validate.

    If baseline is provided, merge form values onto it (preserving keys not edited
    via the UI, such as top-level ``block_fail_mode``, ``meta.name``, and
    ``skills.signature``).
    """
    if baseline is not None:
        data: dict[str, Any] = deepcopy(baseline)
        # Reset the meta block and known sections — everything else is preserved.
        for section in _SECTIONS:
            data.pop(section, None)
    else:
        data = {}

    existing_meta = data.get("meta", {}) if baseline is not None else {}
    new_meta: dict[str, Any] = {
        "schema_version": 1,
        "revision": current_revision + 1,
        "updated_at": datetime.now(UTC).isoformat().replace("+00:00", "Z"),
    }
    if "name" in existing_meta:
        new_meta["name"] = existing_meta["name"]
    data["meta"] = new_meta

    for section, fields in _SECTIONS.items():
        section_data = _section(form, section, fields)
        # Preserve skills.signature (not edited via UI).
        if section == "skills" and baseline is not None:
            sig = baseline.get("skills", {}).get("signature")
            if sig is not None:
                section_data["signature"] = sig
        data[section] = section_data

    # Validate by round-tripping through Policy.
    Policy.model_validate(data)
    return yaml.safe_dump(data, sort_keys=False)
