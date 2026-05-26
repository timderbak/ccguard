"""Convert browser form data → Policy YAML text (validated against schema)."""

from __future__ import annotations

import json
import re
from copy import deepcopy
from datetime import UTC, datetime
from typing import Any, Mapping

import yaml

from ccguard.schemas import Policy


class MandatorySectionError(ValueError):
    """Raised when a `required_*` / `managed_claude_md_blocks` section fails parsing.

    `section` is the section key (e.g. ``required_mcp_servers``) so the route
    handler can render the locked Russian error notice above the correct card.
    """

    def __init__(self, section: str, message: str) -> None:
        super().__init__(message)
        self.section = section


# Locked Russian error notices per 04-UI-SPEC.md Copywriting Contract.
MANDATORY_ERROR_COPY: dict[str, str] = {
    "required_mcp_servers": (
        "Ошибка в MCP-серверах: проверьте name, command и env (валидный JSON)."
    ),
    "required_skills": (
        "Ошибка в скиллах: name обязателен; content не пустой."
    ),
    "required_agents": (
        "Ошибка в агентах: name обязателен; content не пустой."
    ),
    "managed_claude_md_blocks": (
        "Ошибка в блоках: id должен быть kebab-case (буквы/цифры/дефис); "
        "content не пустой."
    ),
}

# WR-02: duplicate-key notices per section (locked Russian copy).
MANDATORY_DUPLICATE_COPY: dict[str, str] = {
    "required_mcp_servers": "Дубликат: name MCP-сервера должен быть уникален.",
    "required_skills": "Дубликат: name скилла должен быть уникален.",
    "required_agents": "Дубликат: name агента должен быть уникален.",
    "managed_claude_md_blocks": "Дубликат: id блока должен быть уникален.",
}

_INDEXED_KEY_RE = re.compile(r"^(?P<prefix>[a-zA-Z_]+)\[(?P<i>\d+)\]\.(?P<field>[a-zA-Z_]+)$")
_KEBAB_RE = re.compile(r"^[a-z0-9]+(-[a-z0-9]+)*$")


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


def parse_indexed_list(
    form: Mapping[str, str], prefix: str
) -> list[dict[str, str]]:
    """Reconstruct an ordered list of dicts from ``{prefix}[{i}].{field}`` form keys.

    Indices are densified — gaps from removed rows collapse to a contiguous
    sequence preserving original order. Empty rows (all fields blank/missing)
    are dropped so admins can leave rows in the UI without persisting them.
    """
    buckets: dict[int, dict[str, str]] = {}
    for raw_key, raw_val in form.items():
        m = _INDEXED_KEY_RE.match(raw_key)
        if m is None:
            continue
        if m.group("prefix") != prefix:
            continue
        idx = int(m.group("i"))
        field = m.group("field")
        buckets.setdefault(idx, {})[field] = raw_val
    out: list[dict[str, str]] = []
    for i in sorted(buckets):
        row = buckets[i]
        if any(v.strip() for v in row.values()):
            out.append(row)
    return out


def _parse_required_mcp_servers(form: Mapping[str, str]) -> list[dict[str, Any]]:
    rows = parse_indexed_list(form, "required_mcp_servers")
    result: list[dict[str, Any]] = []
    seen_names: set[str] = set()
    for row in rows:
        name = row.get("name", "").strip()
        command = row.get("command", "").strip()
        args_raw = row.get("args", "")
        env_raw = row.get("env", "").strip() or "{}"
        if not name or not command:
            raise MandatorySectionError(
                "required_mcp_servers",
                MANDATORY_ERROR_COPY["required_mcp_servers"],
            )
        # WR-02: reject duplicate names so admins see UI feedback instead of
        # silent last-wins overwrite in _merge_mcp_servers on the agent.
        if name in seen_names:
            raise MandatorySectionError(
                "required_mcp_servers",
                MANDATORY_DUPLICATE_COPY["required_mcp_servers"],
            )
        seen_names.add(name)
        try:
            env = json.loads(env_raw)
        except (json.JSONDecodeError, ValueError) as exc:
            raise MandatorySectionError(
                "required_mcp_servers",
                MANDATORY_ERROR_COPY["required_mcp_servers"],
            ) from exc
        if not isinstance(env, dict) or not all(
            isinstance(k, str) and isinstance(v, str) for k, v in env.items()
        ):
            raise MandatorySectionError(
                "required_mcp_servers",
                MANDATORY_ERROR_COPY["required_mcp_servers"],
            )
        # WR-07: args is one-per-line so an argument can contain a literal
        # comma (e.g. ``--filter=a,b``). Previous CSV split silently
        # mangled such args; the UI label was updated in lockstep.
        args = _lines_to_list(args_raw)
        # D-7: inject `_managed_by: "ccguard"` server-side. The alias is
        # serialized back as `_managed_by` (see Policy schema) so the agent in
        # plan 03 can identify managed entries during MCP-config merge.
        result.append(
            {
                "name": name,
                "command": command,
                "args": args,
                "env": env,
                "_managed_by": "ccguard",
            }
        )
    return result


def _parse_required_skills(form: Mapping[str, str]) -> list[dict[str, Any]]:
    rows = parse_indexed_list(form, "required_skills")
    out: list[dict[str, Any]] = []
    seen_names: set[str] = set()
    for row in rows:
        name = row.get("name", "").strip()
        content = row.get("content", "")
        if not name or not content.strip():
            raise MandatorySectionError(
                "required_skills", MANDATORY_ERROR_COPY["required_skills"]
            )
        # WR-02: duplicate names would silently clobber the same file on
        # the agent side (last-wins). Reject at form time.
        if name in seen_names:
            raise MandatorySectionError(
                "required_skills",
                MANDATORY_DUPLICATE_COPY["required_skills"],
            )
        seen_names.add(name)
        out.append(
            {
                "name": name,
                "frontmatter_type": row.get("frontmatter_type", "skill").strip() or "skill",
                "content": content,
            }
        )
    return out


def _parse_required_agents(form: Mapping[str, str]) -> list[dict[str, Any]]:
    rows = parse_indexed_list(form, "required_agents")
    out: list[dict[str, Any]] = []
    seen_names: set[str] = set()
    for row in rows:
        name = row.get("name", "").strip()
        content = row.get("content", "")
        if not name or not content.strip():
            raise MandatorySectionError(
                "required_agents", MANDATORY_ERROR_COPY["required_agents"]
            )
        # WR-02: duplicate agent name clobbers the same file.
        if name in seen_names:
            raise MandatorySectionError(
                "required_agents",
                MANDATORY_DUPLICATE_COPY["required_agents"],
            )
        seen_names.add(name)
        out.append({"name": name, "content": content})
    return out


def _parse_managed_claude_md_blocks(form: Mapping[str, str]) -> list[dict[str, Any]]:
    rows = parse_indexed_list(form, "managed_claude_md_blocks")
    out: list[dict[str, Any]] = []
    seen_ids: set[str] = set()
    for row in rows:
        block_id = row.get("id", "").strip()
        content = row.get("content", "")
        if not _KEBAB_RE.match(block_id) or not content.strip():
            raise MandatorySectionError(
                "managed_claude_md_blocks",
                MANDATORY_ERROR_COPY["managed_claude_md_blocks"],
            )
        # WR-02: duplicate ids — _merge_claude_md_blocks runs sub() twice,
        # second overwrites first, so only one block survives.
        if block_id in seen_ids:
            raise MandatorySectionError(
                "managed_claude_md_blocks",
                MANDATORY_DUPLICATE_COPY["managed_claude_md_blocks"],
            )
        seen_ids.add(block_id)
        out.append(
            {
                "id": block_id,
                "description": row.get("description", ""),
                "content": content,
            }
        )
    return out


def parse_mandatory_sections(form: Mapping[str, str]) -> dict[str, list[dict[str, Any]]]:
    """Parse all 4 mandatory sections. Raises MandatorySectionError on bad input."""
    return {
        "required_mcp_servers": _parse_required_mcp_servers(form),
        "required_skills": _parse_required_skills(form),
        "required_agents": _parse_required_agents(form),
        "managed_claude_md_blocks": _parse_managed_claude_md_blocks(form),
    }


_MANDATORY_SECTIONS = (
    "required_mcp_servers",
    "required_skills",
    "required_agents",
    "managed_claude_md_blocks",
)


def form_to_yaml(
    form: Mapping[str, str],
    *,
    current_revision: int,
    baseline: dict | None = None,
    tab: str = "rules",
) -> str:
    """Serialize form data into Policy YAML. Validates via Policy.model_validate.

    If baseline is provided, merge form values onto it (preserving keys not edited
    via the UI, such as top-level ``block_fail_mode``, ``meta.name``, and
    ``skills.signature``).

    ``tab`` selects which subset of the policy the form is editing:

    * ``"rules"`` (default, /policy) — parse the v0.1 rule sections from the
      form; preserve mandatory sections from the baseline.
    * ``"mandatory"`` (/policy/mandatory) — parse the 4 mandatory sections from
      the form; preserve rule sections from the baseline.
    """
    if baseline is not None:
        data: dict[str, Any] = deepcopy(baseline)
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

    if tab == "mandatory":
        # Parse mandatory sections from form; keep rule sections from baseline.
        mandatory = parse_mandatory_sections(form)
        for section_key in _MANDATORY_SECTIONS:
            data[section_key] = mandatory[section_key]
    else:
        # Default "rules" tab: refresh rule sections from form; preserve mandatory.
        for section in _SECTIONS:
            data.pop(section, None)
        for section, fields in _SECTIONS.items():
            section_data = _section(form, section, fields)
            # Preserve skills.signature (not edited via UI).
            if section == "skills" and baseline is not None:
                sig = baseline.get("skills", {}).get("signature")
                if sig is not None:
                    section_data["signature"] = sig
            data[section] = section_data

    # Validate by round-tripping through Policy. Use by_alias=False since the
    # form-built dict already uses YAML keys (alias form, e.g. `_managed_by`).
    Policy.model_validate(data)
    return yaml.safe_dump(data, sort_keys=False)
