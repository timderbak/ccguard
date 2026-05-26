"""Default regex catalog for prompt-injection scanner (Phase 5 / 05-01).

15 curated patterns across 5 categories — baseline coverage for PI-04. Inputs
are expected to be pre-normalized with NFKC + casefold by the scanner engine
(D-4 in 05-CONTEXT.md), so all patterns are written in lowercase and rely on
`re.IGNORECASE | re.DOTALL` flags only as belt-and-suspenders.

Sources: Anthropic prompt-injection guidance, garak probe taxonomy, llm-attack
corpus. One Cyrillic smoke marker (`игнорируй / забудь … предыдущ / прошл`)
proves the engine path handles non-ASCII; full RU coverage is deferred to v0.3.

Safety:
- No unbounded ``.*`` — every gap uses ``.{0,N}`` with N <= 200 or ``\\s+`` only.
- ReDoS smoke (4KB blob × 5ms) is enforced by
  tests/unit/test_prompt_injection_patterns.py::test_redos_smoke.
- Module has no import-time side effects — `re.compile` runs lazily through
  `get_default_patterns()` (lru_cache=1).
"""

from __future__ import annotations

import re
from functools import lru_cache

_FLAGS = re.IGNORECASE | re.DOTALL

# (category, raw regex) — compiled lazily inside get_default_patterns().
_DEFAULTS: tuple[tuple[str, str], ...] = (
    # --- ignore_previous_instructions (4 patterns incl. Cyrillic smoke) ---
    (
        "ignore_previous_instructions",
        r"ignore\s+(?:all\s+)?(?:previous|prior|above|earlier)\s+"
        r"(?:instructions?|prompts?|messages?|directives?|rules?)",
    ),
    (
        "ignore_previous_instructions",
        r"disregard\s+(?:all\s+|any\s+)?(?:previous|prior|above|earlier)\s+"
        r"(?:instructions?|prompts?|messages?|directives?|rules?)",
    ),
    (
        "ignore_previous_instructions",
        r"forget\s+(?:everything|all|what)\s+(?:you\s+)?(?:were|have\s+been|was)?\s*"
        r"(?:told|said|instructed|taught)",
    ),
    # Cyrillic smoke marker (D-4): "игнорируй (все) предыдущие" / "забудь прошлые".
    (
        "ignore_previous_instructions",
        r"(?:игнорируй|забудь)\s+(?:все\s+)?(?:предыдущ|прошл)",
    ),
    # WR-09: mixed-script doppelgangers — Cyrillic homoglyphs substituted
    # into Latin "ignore"/"forget" forms (NFKC does NOT collapse these,
    # so a literal pattern per shape is the cheapest mitigation short of
    # pulling a confusables map). Character classes group the Latin
    # codepoint with its visually-identical Cyrillic counterpart so any
    # 1–N substitution variant matches the same rule:
    #   i  ↔ і (U+0456)
    #   g  ↔ ɡ (U+0261) — also Latin small g
    #   n  ↔ п  ... no, п is visually distinct; n has no perfect Cyr twin
    #   o  ↔ о (U+043E)
    #   r  ↔ г (U+0433 — used colloquially as r-shape)
    #   e  ↔ е (U+0435)
    # The "ignore"/"забудь" base words are also globbed to keep coverage
    # broad without hand-crafting every permutation.
    (
        "ignore_previous_instructions",
        r"[iіI][gɡG][nN][оoO][rгR][eеE]\s+(?:previous|prior|above|earlier)",
    ),
    (
        "ignore_previous_instructions",
        r"[fF][оoO][rгR][gɡG][eеE][tT]\s+(?:previous|prior|earlier|everything)",
    ),
    (
        "ignore_previous_instructions",
        # Cyrillic "забудь" with a Latin/Cyrillic mix on a/у/д/ь
        r"[зz][аaA][бbB][уyуu][дdD][ьb’]\s+(?:все|предыдущ|прошл)",
    ),
    (
        "ignore_previous_instructions",
        # "игнорируй" with Latin doppelgangers on и/н/о/р/у/й
        r"[иiI][гgG][нnN][оoO][рrR][иiI][рrR][уyуu][йjy]\s+(?:все|предыдущ|прошл)",
    ),
    # --- instruction_override (3 patterns) ---
    (
        "instruction_override",
        r"new\s+system\s+(?:prompt|message|instruction)s?\s*[:.\-=]",
    ),
    (
        "instruction_override",
        r"<\s*/?\s*(?:system|admin|root|sudo)\s*>",
    ),
    (
        "instruction_override",
        r"(?:override|replace|update)\s+(?:the\s+|your\s+)?(?:system|previous|original)\s+"
        r"(?:prompt|instructions?|rules?|directives?)",
    ),
    # --- role_swap (3 patterns) ---
    (
        "role_swap",
        r"you\s+are\s+(?:now\s+)?(?:a\s+|an\s+)?"
        r"(?:different|new|unrestricted|uncensored|jailbroken|evil)\s+"
        r"(?:\w+\s+){0,3}?(?:ai|assistant|model|chatbot|bot|persona)?",
    ),
    (
        "role_swap",
        r"\bact\s+as\s+(?:dan|aim|stan|dude|kevin|niccolo|machiavelli)\b",
    ),
    (
        "role_swap",
        r"pretend\s+(?:you\s+|to\s+)(?:are|have|be|don't\s+have)\s+"
        r"(?:no|a|an|without|free\s+of|unrestricted|uncensored)",
    ),
    # --- jailbreak_template (3 patterns) ---
    (
        "jailbreak_template",
        r"\bdan\s+(?:mode|prompt|jailbreak)\b",
    ),
    (
        "jailbreak_template",
        r"developer\s+mode\s+(?:enabled|activated|on|engaged|unlocked)",
    ),
    (
        "jailbreak_template",
        r"\bopposite\s+day\b",
    ),
    # --- base64_encoded_prompt (2 patterns) ---
    (
        "base64_encoded_prompt",
        # Explicit base64 prefix immediately followed by a substantive blob.
        r"\bbase64\s*[:=]\s*[A-Za-z0-9+/=]{20,}",
    ),
    (
        "base64_encoded_prompt",
        # Instruction to decode something as base64 — the keyword pins it.
        r"decode\s+(?:the\s+following\s+|this\s+)?(?:as\s+)?base64",
    ),
)


@lru_cache(maxsize=1)
def get_default_patterns() -> tuple[tuple[str, re.Pattern[str]], ...]:
    """Return compiled default pattern catalog (idempotent via lru_cache).

    Two calls return the SAME tuple object — verified by
    test_get_default_patterns_is_cached.
    """
    return tuple((cat, re.compile(src, _FLAGS)) for cat, src in _DEFAULTS)
