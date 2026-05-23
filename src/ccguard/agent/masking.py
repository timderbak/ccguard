"""Маскирование секретов перед попаданием в findings/audit."""

from __future__ import annotations

import re

_SECRET_PATTERNS: list[re.Pattern[str]] = [
    re.compile(r"sk-[A-Za-z0-9]{20,}"),  # OpenAI-style
    re.compile(r"sk-ant-[A-Za-z0-9_-]{20,}"),  # Anthropic
    re.compile(r"ghp_[A-Za-z0-9]{20,}"),  # GitHub PAT
    re.compile(r"gho_[A-Za-z0-9]{20,}"),
    re.compile(r"ghs_[A-Za-z0-9]{20,}"),
    re.compile(r"AKIA[A-Z0-9]{16}"),  # AWS access key
    re.compile(r"AIza[A-Za-z0-9_-]{30,}"),  # Google API key
    re.compile(r"xox[bpa]-[A-Za-z0-9-]{20,}"),  # Slack
    re.compile(r"eyJ[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{20,}"),  # JWT
    re.compile(r"(?i)(?:password|token|secret|api[_-]?key)\s*[:=]\s*['\"]?[A-Za-z0-9_\-]{8,}"),
]

_MASK = "***MASKED***"
_MAX_LEN = 200


def mask_secrets(value: str | None) -> str | None:
    if value is None:
        return None
    masked = value
    for pat in _SECRET_PATTERNS:
        masked = pat.sub(_MASK, masked)
    if len(masked) > _MAX_LEN:
        masked = masked[:_MAX_LEN] + "...[truncated]"
    return masked
