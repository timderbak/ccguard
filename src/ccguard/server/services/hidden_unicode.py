"""Detect hidden / invisible Unicode in text that reaches the LLM as instructions.

Attackers hide characters a human reviewer cannot see but the model still reads:
zero-width spaces splitting a banned word (``ig<ZWSP>nore``), bidirectional
overrides reordering displayed text ("Trojan Source"), and Unicode Tag characters
smuggling ASCII. Real-world: the "Rules File Backdoor" (Pillar, Mar 2025) and the
GlassWorm OpenVSX worm (Oct 2025) both weaponized invisible Unicode in AI-readable
config.

This is a PURE, deterministic detector — no LLM, no regex catalog. It flags only
codepoints that are **never legitimate** in a config description / instruction, so
it does not false-positive:

* invisible / zero-width formatting: ZWSP, word-joiner, BOM, soft-hyphen, MVS;
* bidirectional controls: embeddings / overrides / isolates (the Trojan-Source set);
* Unicode Tag block (U+E0000–U+E007F).

Deliberately EXCLUDED to stay false-positive-free: ZWJ / ZWNJ (U+200D / U+200C) —
they are legitimate in emoji sequences (👨‍👩‍👧) and several scripts, so flagging
them would misfire on ordinary text. Homoglyphs (Cyrillic/Greek look-alikes) are
also out of scope here: legitimate non-Latin text (e.g. Russian descriptions) uses
them normally, so homoglyph detection needs context this deterministic pass lacks.
"""
from __future__ import annotations

import unicodedata
from dataclasses import dataclass

# Invisible / zero-width formatting characters (no visible glyph, no legit role in
# a description). ZWJ/ZWNJ intentionally omitted — see module docstring.
_INVISIBLE: frozenset[int] = frozenset(
    {
        0x200B,  # ZERO WIDTH SPACE
        0x2060,  # WORD JOINER
        0xFEFF,  # ZERO WIDTH NO-BREAK SPACE / BOM
        0x00AD,  # SOFT HYPHEN
        0x180E,  # MONGOLIAN VOWEL SEPARATOR
        0x2061,  # FUNCTION APPLICATION
        0x2062,  # INVISIBLE TIMES
        0x2063,  # INVISIBLE SEPARATOR
        0x2064,  # INVISIBLE PLUS
    }
)
# Bidirectional control characters — the "Trojan Source" reordering family.
_BIDI: frozenset[int] = frozenset(
    set(range(0x202A, 0x202F))  # LRE LRE RLE PDF LRO RLO (0x202A–0x202E)
    | set(range(0x2066, 0x206A))  # LRI RLI FSI PDI (isolates)
)
# Unicode Tag block — historically used to smuggle hidden ASCII into text.
_TAGS: frozenset[int] = frozenset(range(0xE0000, 0xE0080))

_SUSPICIOUS: frozenset[int] = _INVISIBLE | _BIDI | _TAGS

_MAX_SAMPLES = 10


@dataclass(frozen=True)
class HiddenUnicodeHit:
    codepoint: int
    name: str
    position: int

    @property
    def hex(self) -> str:
        return f"U+{self.codepoint:04X}"


@dataclass(frozen=True)
class HiddenUnicodeResult:
    found: bool
    count: int
    categories: tuple[str, ...]           # "invisible" / "bidi" / "tag"
    samples: tuple[HiddenUnicodeHit, ...]  # first _MAX_SAMPLES, for the finding

    def summary(self) -> str:
        cats = ", ".join(self.categories)
        return f"{self.count} скрытых Unicode-символов ({cats})"


def _category(cp: int) -> str:
    if cp in _BIDI:
        return "bidi"
    if cp in _TAGS:
        return "tag"
    return "invisible"


def scan_hidden_unicode(text: str | None) -> HiddenUnicodeResult:
    """Return every never-legitimate hidden codepoint in ``text``.

    Empty/None → ``found=False``. Position is the character index. ``name`` is the
    Unicode name (or ``"<unnamed>"``). Never raises.
    """
    if not text:
        return HiddenUnicodeResult(False, 0, (), ())
    hits: list[HiddenUnicodeHit] = []
    cats: set[str] = set()
    for i, ch in enumerate(text):
        cp = ord(ch)
        if cp in _SUSPICIOUS:
            cats.add(_category(cp))
            if len(hits) < _MAX_SAMPLES:
                try:
                    name = unicodedata.name(ch)
                except ValueError:
                    name = "<unnamed>"
                hits.append(HiddenUnicodeHit(cp, name, i))
    count = sum(1 for ch in text if ord(ch) in _SUSPICIOUS)
    # Stable category order for deterministic findings.
    ordered = tuple(c for c in ("invisible", "bidi", "tag") if c in cats)
    return HiddenUnicodeResult(count > 0, count, ordered, tuple(hits))
