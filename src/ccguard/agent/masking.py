"""Single source of secret-regex truth for the agent.

Two consumers share the regex set:

* :func:`mask_secrets` — used by inventory/audit findings; truncates to 200
  chars because findings are short user-facing strings. Existing v0.1 API,
  preserved verbatim for backward compatibility with all callers.
* :func:`mask_content` — used by Plan 03-04 content scanner; applies the same
  regex set WITHOUT truncation so the LLM still sees a full document. This is
  the function the agent calls before base64-encoding scannable file content.

When adding a new secret pattern, append to ``_SECRET_PATTERNS`` and both
consumers pick it up automatically (T-03-10 mitigation, Plan 03-04).
"""

from __future__ import annotations

import re

_SECRET_PATTERNS: list[re.Pattern[str]] = [
    re.compile(r"sk-[A-Za-z0-9]{20,}"),  # OpenAI-style
    re.compile(r"sk-ant-[A-Za-z0-9_-]{20,}"),  # Anthropic
    re.compile(r"ghp_[A-Za-z0-9]{20,}"),  # GitHub PAT
    re.compile(r"gho_[A-Za-z0-9]{20,}"),
    re.compile(r"ghs_[A-Za-z0-9]{20,}"),
    re.compile(r"glpat-[A-Za-z0-9_-]{20,}"),  # GitLab PAT
    re.compile(r"AKIA[A-Z0-9]{16}"),  # AWS access key
    re.compile(r"AIza[A-Za-z0-9_-]{30,}"),  # Google API key
    re.compile(r"xox[bpa]-[A-Za-z0-9-]{20,}"),  # Slack
    re.compile(r"eyJ[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{20,}"),  # JWT
    re.compile(r"(?i)(?:password|token|secret|api[_-]?key)\s*[:=]\s*['\"]?[A-Za-z0-9_\-]{8,}"),
]

_MASK = "***MASKED***"
_MAX_LEN = 200


def mask_secrets(value: str | None) -> str | None:
    """Mask secrets in a short string. Truncates to 200 chars.

    Used by inventory/audit findings (rule_id matches, matched_value display).
    Do NOT use for content-scanning input — truncation throws away most of the
    file. Use :func:`mask_content` instead.
    """
    if value is None:
        return None
    masked = value
    for pat in _SECRET_PATTERNS:
        masked = pat.sub(_MASK, masked)
    if len(masked) > _MAX_LEN:
        masked = masked[:_MAX_LEN] + "...[truncated]"
    return masked


def mask_content(value: str) -> str:
    """Mask secrets in arbitrary-length text WITHOUT truncating.

    Plan 03-04 LLM content scanner: agent calls this on each ``~/.claude/agents/*.md``
    and ``~/.claude/skills/*/SKILL.md`` file BEFORE base64-encoding and sending.
    Idempotent — running twice produces the same output (the mask token does
    not match any regex). The same secret-pattern set as :func:`mask_secrets`
    ensures we never accidentally have masking-coverage drift between
    inventory findings and content scanning.
    """
    out = value
    for pat in _SECRET_PATTERNS:
        out = pat.sub(_MASK, out)
    return out
