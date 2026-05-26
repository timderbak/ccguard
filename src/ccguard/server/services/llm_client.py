"""Anthropic SDK wrapper for the LLM content scanner.

This module is the *only* place that talks to Anthropic. It exposes:

- `LLMClient.scan_content(content, file_path, scope) -> ScanOutcome`
- `ScanOutcome` dataclass (risk_score, category, rationale, tokens, cost, model)
- `LLMClientError(retryable: bool)` for upstream retry/budget decisions

Design notes (locked in CONTEXT.md / RESEARCH.md):
- D-02: one-pass protocol — agent sends content+hash in one call; we don't re-prompt.
- D-05: tool_use with `strict: true` for reliable JSON.
- D-06: Haiku 4.5 pricing — $1/MTok input, $5/MTok output (NOT retired Haiku 3.5 rates).
- Fail-safe: any malformed branch returns a conservative synthetic outcome
  (risk_score=50, category="benign", rationale="scanner_error: ...") instead of raising.
- Network/API errors raise `LLMClientError` — scan_service decides retry/budget policy.
"""

from __future__ import annotations

import math
from dataclasses import dataclass
from typing import Any, Final, Literal

import anthropic

# --- Constants -------------------------------------------------------------

MODEL: Final[str] = "claude-haiku-4-5-20251001"
MAX_TOKENS: Final[int] = 512

# WR-03: per-request HTTP timeout for Anthropic SDK calls. Without this, the
# SDK default (10 minutes) lets a hung API call hold ScanService._lock for
# the same duration, freezing the scanner subsystem. Mirror the agent-side
# DEFAULT_TIMEOUT_SEC=30.0 from inventory_scan.py.
LLM_REQUEST_TIMEOUT_SEC: Final[float] = 30.0

# Haiku 4.5 pricing — D-06.
INPUT_CENTS_PER_MTOK: Final[int] = 100  # $1 / MTok input
OUTPUT_CENTS_PER_MTOK: Final[int] = 500  # $5 / MTok output

CATEGORIES: Final[tuple[str, ...]] = (
    "jailbreak",
    "prompt-injection-template",
    "data-exfil",
    "privilege-escalation",
    "benign",
)

REPORT_RISK_TOOL: Final[dict[str, Any]] = {
    "name": "report_risk",
    "description": "Report the risk classification of the scanned content.",
    "input_schema": {
        "type": "object",
        "properties": {
            "risk_score": {"type": "integer", "minimum": 0, "maximum": 100},
            "category": {"type": "string", "enum": list(CATEGORIES)},
            "rationale": {"type": "string", "maxLength": 500},
        },
        "required": ["risk_score", "category", "rationale"],
    },
    "strict": True,
}

SYSTEM_PROMPT: Final[str] = (
    "You are a security classifier for AI-agent configuration files "
    "(Claude Code agents and skills). Classify the supplied content into one "
    "risk category and assign a risk_score 0-100. Always respond by invoking "
    "the `report_risk` tool exactly once. Never reply with prose."
)


# --- Types -----------------------------------------------------------------


@dataclass(frozen=True)
class ScanOutcome:
    """Structured result of a single content scan."""

    risk_score: int
    category: str
    rationale: str
    input_tokens: int
    output_tokens: int
    cost_cents: int
    model: str


class LLMClientError(Exception):
    """Raised on transport-level failures (network, API errors).

    `retryable=True` signals the caller may retry; False indicates a permanent
    failure (e.g. auth, billing) that should be surfaced to the operator.
    """

    def __init__(self, message: str, *, retryable: bool) -> None:
        super().__init__(message)
        self.retryable = retryable


# --- Pricing helper --------------------------------------------------------


def _compute_cost_cents(input_tokens: int, output_tokens: int) -> int:
    """Return cost in cents using Haiku 4.5 pricing (D-06).

    Formula: ceil((in * 100 + out * 500) / 1_000_000)
    math.ceil ensures any non-zero usage costs at least 1 cent (safe rounding
    for budget accounting; we never under-report cost).
    """
    raw = input_tokens * INPUT_CENTS_PER_MTOK + output_tokens * OUTPUT_CENTS_PER_MTOK
    if raw <= 0:
        return 0
    return math.ceil(raw / 1_000_000)


# --- Synthetic fail-safe ---------------------------------------------------


def _synthetic_outcome(
    *,
    reason: str,
    input_tokens: int,
    output_tokens: int,
) -> ScanOutcome:
    """Build a conservative fail-safe outcome (risk_score=50, category=benign)."""
    return ScanOutcome(
        risk_score=50,
        category="benign",
        rationale=f"scanner_error: {reason}",
        input_tokens=input_tokens,
        output_tokens=output_tokens,
        cost_cents=_compute_cost_cents(input_tokens, output_tokens),
        model=MODEL,
    )


# --- Parsing helpers -------------------------------------------------------


def _extract_tool_use(response: Any) -> dict[str, Any] | None:
    """Return the report_risk tool_use input dict, or None if not present."""
    for block in getattr(response, "content", []) or []:
        if getattr(block, "type", None) == "tool_use" and getattr(block, "name", None) == "report_risk":
            inp = getattr(block, "input", None)
            if isinstance(inp, dict):
                return inp
    return None


def _parse_tool_use(
    tool_input: dict[str, Any],
    input_tokens: int,
    output_tokens: int,
) -> ScanOutcome:
    """Validate and parse the tool_use dict into a ScanOutcome.

    Returns a synthetic fail-safe on any validation failure.
    """
    # Required fields present?
    for field in ("risk_score", "category", "rationale"):
        if field not in tool_input:
            return _synthetic_outcome(
                reason=f"missing field {field}",
                input_tokens=input_tokens,
                output_tokens=output_tokens,
            )

    risk_score = tool_input["risk_score"]
    category = tool_input["category"]
    rationale = tool_input["rationale"]

    # Type / range validation.
    if not isinstance(risk_score, int) or not (0 <= risk_score <= 100):
        return _synthetic_outcome(
            reason=f"risk_score out of range: {risk_score!r}",
            input_tokens=input_tokens,
            output_tokens=output_tokens,
        )
    if not isinstance(category, str) or category not in CATEGORIES:
        return _synthetic_outcome(
            reason=f"unknown category {category!r}",
            input_tokens=input_tokens,
            output_tokens=output_tokens,
        )
    if not isinstance(rationale, str):
        return _synthetic_outcome(
            reason="rationale not a string",
            input_tokens=input_tokens,
            output_tokens=output_tokens,
        )

    return ScanOutcome(
        risk_score=risk_score,
        category=category,
        rationale=rationale[:500],  # defensive truncate
        input_tokens=input_tokens,
        output_tokens=output_tokens,
        cost_cents=_compute_cost_cents(input_tokens, output_tokens),
        model=MODEL,
    )


# --- Client ----------------------------------------------------------------


class LLMClient:
    """Single-purpose async wrapper around `anthropic.AsyncAnthropic`."""

    def __init__(self, api_key: str) -> None:
        # WR-03: cap per-request HTTP timeout so a hung Anthropic call cannot
        # hold ScanService._lock for the SDK default (10 minutes).
        self._client = anthropic.AsyncAnthropic(
            api_key=api_key, timeout=LLM_REQUEST_TIMEOUT_SEC
        )

    async def scan_content(
        self,
        content: str,
        file_path: str,
        scope: Literal["agent", "skill"],
    ) -> ScanOutcome:
        """Scan one file's content and return a structured ScanOutcome.

        - On valid tool_use: parsed result with computed cost.
        - On any malformed/missing tool_use: conservative synthetic outcome.
        - On transport/API error: raises LLMClientError(retryable=...).
        """
        user_msg = f"file_path: {file_path}\nscope: {scope}\n---\n{content}"

        try:
            response = await self._client.messages.create(
                model=MODEL,
                max_tokens=MAX_TOKENS,
                system=SYSTEM_PROMPT,
                messages=[{"role": "user", "content": user_msg}],
                tools=[REPORT_RISK_TOOL],
                tool_choice={"type": "tool", "name": "report_risk"},
            )
        except anthropic.APIConnectionError as exc:
            raise LLMClientError(f"network error: {exc}", retryable=True) from exc
        except anthropic.RateLimitError as exc:
            raise LLMClientError(f"rate limited: {exc}", retryable=True) from exc
        except anthropic.APIStatusError as exc:
            # 5xx → retryable; 4xx → not retryable.
            status = getattr(exc, "status_code", 0) or 0
            retryable = status >= 500
            raise LLMClientError(f"api error {status}: {exc}", retryable=retryable) from exc
        except anthropic.APIError as exc:
            raise LLMClientError(f"api error: {exc}", retryable=False) from exc

        usage = getattr(response, "usage", None)
        input_tokens = int(getattr(usage, "input_tokens", 0) or 0)
        output_tokens = int(getattr(usage, "output_tokens", 0) or 0)

        tool_input = _extract_tool_use(response)
        if tool_input is None:
            return _synthetic_outcome(
                reason="no tool_use in response",
                input_tokens=input_tokens,
                output_tokens=output_tokens,
            )

        return _parse_tool_use(tool_input, input_tokens, output_tokens)
