"""Shared, bounded, fail-open command normalizer (Phase 1 / P1 + anti-obfuscation).

De-obfuscates a bash command BEFORE matchers (enforce + signal-extraction) run,
so encoded/indirected payloads are matched on clean text instead of slipping
through raw-string regexes. Pure: no I/O, no shell execution, never raises.

Anti-obfuscation is ITERATIVE but hard-bounded (a multiplier on every signal —
hardening this lifts all matchers at once, while staying a small slice of the
<100ms PreToolUse budget):

  * quote-noise stripping runs to a fixpoint (``c'u'r"l"`` → ``curl``);
  * variable indirection resolves chained assignments (``A=cu;B=rl;C=$A$B;$C``);
  * base64/hex blobs are decoded LAYER BY LAYER (double/nested encoding), each
    layer re-scanned, capped by ``_MAX_BLOBS`` and ``_MAX_PASSES``;
  * ANSI-C / printf escapes (``$'\\x63url'``, ``printf '\\x63\\x75\\x72\\x6c'``)
    are unescaped.

Every loop is bounded; a junk-decode filter (``_looks_like_command``) keeps an
opaque blob (git SHA, integrity hash) from forging a signal.
"""
from __future__ import annotations

import base64
import binascii
import re
import shlex
from dataclasses import dataclass, field

# Hard bounds — normalization is a small slice of the <100ms PreToolUse budget.
_MAX_INPUT = 64_000          # chars; larger → fail-open to raw
_MAX_BLOBS = 12              # base64/hex/ansi blobs decoded per command (all layers)
_MAX_VARS = 32               # simple var assignments tracked
_MAX_PASSES = 4              # decode layers (double/triple/quad encoding)
_MAX_FIXPOINT = 5            # iterations for quote-strip / var-expand fixpoints

_B64_TOKEN = re.compile(r"[A-Za-z0-9+/]{16,}={0,2}")
# Hex: contiguous \xHH runs (≥3 → catches short payloads like "curl"), OR a long
# bare-hex run (≥16, high to avoid git-SHA / token false positives).
_HEX_TOKEN = re.compile(r"(?:\\x[0-9a-fA-F]{2}){3,}|\b[0-9a-fA-F]{16,}\b")
_ASSIGN = re.compile(r"^([A-Za-z_][A-Za-z0-9_]*)=(.+)$")
_URL_LITERAL = re.compile(r"https?://\S+", re.IGNORECASE)
_VAR_REF = re.compile(r"\$\{([A-Za-z_]\w*)\}|\$([A-Za-z_]\w*)")
# bash substring slicing ${name:off:len} / ${name:off} — a common carve trick
_VAR_SLICE = re.compile(r"\$\{([A-Za-z_]\w*):(\d+)(?::(\d+))?\}")
_QUOTE_NOISE = re.compile(r"(\w)['\"]+(\w)")
# Single/double-quoted literal BODIES — the carrier of a rev/tr-ciphered payload.
_QUOTED_LITERAL = re.compile(r"'([^']*)'|\"([^\"]*)\"")
# ANSI-C / printf string bodies: $'...'  or  printf [-v x] '...' / "..."
_ANSI_C = re.compile(r"\$'([^']*)'|printf\s+(?:-v\s+\w+\s+)?['\"]([^'\"]*)['\"]")
_C_ESCAPE = re.compile(r"\\x[0-9a-fA-F]{2}|\\[0-7]{1,3}")
# Interpreter-aware (python -c / node -e / ...) char-code assembly: a bracketed
# integer list (map(chr,[..]) / bytes([..]) / [..]) or JS String.fromCharCode(..).
_INT_LIST = re.compile(r"\[\s*(\d{1,7}(?:\s*,\s*\d{1,7}){2,})\s*\]")
_FROMCHARCODE = re.compile(r"fromCharCode\s*\(\s*([\d,\s]+)\)", re.IGNORECASE)
_CHR_CHAIN = re.compile(r"(?:chr\(\s*\d{1,7}\s*\)\s*[+,]?\s*){3,}")
# String concatenation of literals: 'a'+'b'+'c' (py/js) or 'a'.'b' (php).
_CONCAT = re.compile(r"(['\"])(?:(?!\1).){0,200}\1(?:\s*[.+]\s*(['\"])(?:(?!\2).){0,200}\2){1,30}")


@dataclass(frozen=True)
class NormalizedCommand:
    raw: str
    statements: list[str] = field(default_factory=list)
    decoded_blobs: list[str] = field(default_factory=list)
    text: str = ""
    urls: list[str] = field(default_factory=list)


def _strip_noise(s: str) -> str:
    s = s.replace("${IFS}", " ").replace("$IFS", " ")
    # collapse intra-token quote noise to a FIXPOINT: c'u'r"l" -> curl. One
    # re.sub pass is non-overlapping, so a chain needs several passes.
    for _ in range(_MAX_FIXPOINT):
        ns = _QUOTE_NOISE.sub(r"\1\2", s)
        if ns == s:
            break
        s = ns
    return s


def _split_statements(command: str) -> list[str]:
    parts: list[str] = []
    buf: list[str] = []
    in_s = in_d = False
    i = 0
    while i < len(command):
        ch = command[i]
        if ch == "'" and not in_d:
            in_s = not in_s
            buf.append(ch)
        elif ch == '"' and not in_s:
            in_d = not in_d
            buf.append(ch)
        elif not in_s and not in_d:
            if ch in "|&;" and i + 1 < len(command) and command[i + 1] == ch:
                parts.append("".join(buf))
                buf = []
                i += 2
                continue
            if ch in "|;\n":
                parts.append("".join(buf))
                buf = []
                i += 1
                continue
            buf.append(ch)
        else:
            buf.append(ch)
        i += 1
    parts.append("".join(buf))
    return [p.strip() for p in parts if p.strip()]


def _expand_once(text: str, vars_: dict[str, str]) -> str:
    if not vars_:
        return text

    def slice_repl(m: re.Match[str]) -> str:
        v = vars_.get(m.group(1))
        if v is None:
            return m.group(0)
        off = int(m.group(2))
        return v[off : off + int(m.group(3))] if m.group(3) else v[off:]

    text = _VAR_SLICE.sub(slice_repl, text)

    def repl(m: re.Match[str]) -> str:
        name = m.group(1) or m.group(2)
        return vars_.get(name, m.group(0))

    return _VAR_REF.sub(repl, text)


def _expand_vars(text: str, vars_: dict[str, str]) -> str:
    """Expand $VAR / ${VAR} to a fixpoint (chained indirection)."""
    if not vars_:
        return text
    for _ in range(_MAX_FIXPOINT):
        nt = _expand_once(text, vars_)
        if nt == text:
            break
        text = nt
    return text


def _collect_vars(statements: list[str]) -> dict[str, str]:
    out: dict[str, str] = {}
    for st in statements:
        m = _ASSIGN.match(st.strip())
        if m and len(out) < _MAX_VARS:
            out[m.group(1)] = m.group(2).strip().strip("'\"")
    # resolve chained assignments (C=$A$B) to a fixpoint so $C expands fully
    for _ in range(_MAX_FIXPOINT):
        changed = False
        for k in list(out):
            nv = _expand_once(out[k], out)
            if nv != out[k]:
                out[k] = nv
                changed = True
        if not changed:
            break
    return out


_CMD_CHARS = set(" ./:_-@|=\"'$(){}[]<>~&;*+,!?")


def _looks_like_command(dec: str) -> bool:
    """Only merge a decoded blob into the search surface if it plausibly holds
    shell/command text: ASCII, length >= 4, and >=85% command-like chars. This
    rejects random hex/base64 (git SHAs, opaque tokens) that decode to printable
    junk and could otherwise forge a signal (review should-fix)."""
    if len(dec) < 4 or not dec.isascii() or not dec.isprintable():
        return False
    good = sum(1 for c in dec if c.isalnum() or c in _CMD_CHARS)
    return good / len(dec) >= 0.85


def _decode_blobs_once(text: str) -> list[str]:
    """One layer: decode base64/hex blobs found in ``text``."""
    out: list[str] = []
    for m in _B64_TOKEN.finditer(text):
        if len(out) >= _MAX_BLOBS:
            break
        tok = m.group(0)
        try:
            dec = base64.b64decode(tok, validate=True).decode("utf-8", "ignore")
        except (binascii.Error, ValueError):
            continue
        if _looks_like_command(dec):
            out.append(dec)
    for m in _HEX_TOKEN.finditer(text):
        if len(out) >= _MAX_BLOBS:
            break
        raw = m.group(0).replace("\\x", "")
        if len(raw) % 2:
            continue
        try:
            dec = bytes.fromhex(raw).decode("utf-8", "ignore")
        except ValueError:
            continue
        if _looks_like_command(dec):
            out.append(dec)
    return out


def _decode_iter(text: str) -> list[str]:
    """Decode LAYER BY LAYER: a decoded blob may itself contain another blob
    (double/triple base64). Bounded by ``_MAX_PASSES`` and ``_MAX_BLOBS``; a
    ``seen`` set prevents re-decoding the same layer."""
    out: list[str] = []
    seen: set[str] = set()
    frontier = [text]
    for _ in range(_MAX_PASSES):
        nxt: list[str] = []
        for t in frontier:
            for dec in _decode_blobs_once(t):
                if len(out) >= _MAX_BLOBS:
                    return out
                if dec in seen:
                    continue
                seen.add(dec)
                out.append(dec)
                nxt.append(dec)
        if not nxt:
            break
        frontier = nxt
    return out


def _unescape_c(s: str) -> str:
    def repl(m: re.Match[str]) -> str:
        g = m.group(0)
        try:
            if g[1] in "xX":
                return chr(int(g[2:], 16))
            return chr(int(g[1:], 8) & 0xFF)  # octal \nnn
        except ValueError:
            return g

    return _C_ESCAPE.sub(repl, s)


def _unescape_inline(text: str) -> str:
    """Decode ANSI-C / printf escape strings IN PLACE so the result stays glued
    to its context: ``$'\\x6e\\x63' -e /bin/sh`` → ``nc -e /bin/sh``,
    ``$(printf '\\x63\\x75\\x72\\x6c') url`` → ``$(curl) url``. Returns a
    transform of the real command (not an opaque blob), so no junk filter is
    needed — it can only REMOVE obfuscation, never forge new tokens."""

    def repl(m: re.Match[str]) -> str:
        body = m.group(1) if m.group(1) is not None else m.group(2)
        if not body or "\\" not in body:
            return m.group(0)
        return _unescape_c(body)

    return _ANSI_C.sub(repl, text)


def _expand_tr_set(s: str) -> str:
    """Expand a ``tr`` SET argument: ranges (``a-z``) and simple backslash
    escapes. Bounded by input length; never raises."""
    if "\\" in s:
        try:
            s = s.encode("latin-1", "ignore").decode("unicode_escape", "ignore")
        except (UnicodeDecodeError, UnicodeEncodeError):
            pass
    out: list[str] = []
    i = 0
    n = len(s)
    while i < n and len(out) < 256:
        if i + 2 < n and s[i + 1] == "-" and s[i] <= s[i + 2]:
            for c in range(ord(s[i]), ord(s[i + 2]) + 1):
                out.append(chr(c))
            i += 3
        else:
            out.append(s[i])
            i += 1
    return "".join(out)


def _build_tr_map(set1: str, set2: str) -> dict[str, str] | None:
    """Build a char-substitution table from a ``tr SET1 SET2`` pair (covers
    ROT13 and any monoalphabetic cipher). ``None`` if either set is empty."""
    a = _expand_tr_set(set1)
    b = _expand_tr_set(set2)
    if not a or not b:
        return None
    if len(b) < len(a):  # tr repeats SET2's last char to pad
        b = b + b[-1] * (len(a) - len(b))
    return {x: y for x, y in zip(a, b[: len(a)], strict=False) if x != y}


def _charmap_candidates(statements: list[str]) -> list[str]:
    """Carrier strings a rev/tr transform could hide a command in: quoted
    literals + ``echo``/``printf`` arguments, across all statements."""
    cand: list[str] = []
    seen: set[str] = set()

    def _add(s: str) -> None:
        if s and s not in seen:
            seen.add(s)
            cand.append(s)

    for st in statements:
        for m in _QUOTED_LITERAL.finditer(st):
            _add(m.group(1) if m.group(1) is not None else m.group(2))
        # strip command-substitution punctuation so `$(echo x` tokenizes cleanly
        clean = st.replace("$(", " ").replace("`", " ").replace(")", " ")
        try:
            toks = shlex.split(clean, posix=True)
        except ValueError:
            toks = clean.split()
        for idx, tok in enumerate(toks):
            if tok.rsplit("/", 1)[-1] in {"echo", "printf"}:
                for arg in toks[idx + 1 :]:
                    if not arg.startswith("-"):
                        _add(arg)
    return cand


def _charmap_decode(statements: list[str]) -> list[str]:
    """De-obfuscate ``rev`` (string reversal) and ``tr`` (charmap/ROT cipher).

    Only fires when a ``rev``/``tr`` command word is present; ``tr`` with
    delete/squeeze/complement flags is skipped (not a substitution). Outputs are
    candidate blobs run through ``_looks_like_command`` — they can only ADD a
    de-obfuscated string to the search surface, never forge a benign signal."""
    has_rev = False
    tr_maps: list[dict[str, str]] = []
    for st in statements:
        clean = st.replace("$(", " ").replace("`", " ").replace(")", " ")
        try:
            toks = shlex.split(clean, posix=True)
        except ValueError:
            toks = clean.split()
        i = 0
        while i < len(toks):
            base = toks[i].rsplit("/", 1)[-1]
            if base == "rev":
                has_rev = True
            elif base == "tr":
                sets: list[str] = []
                bad = False
                for a in toks[i + 1 :]:
                    if a.startswith("-") and len(a) > 1:
                        if any(f in a[1:] for f in "dsc"):
                            bad = True
                            break
                        continue  # unrelated flag (e.g. -t)
                    sets.append(a)
                    if len(sets) == 2:
                        break
                if not bad and len(sets) == 2:
                    mp = _build_tr_map(sets[0], sets[1])
                    if mp:
                        tr_maps.append(mp)
            i += 1
    if not has_rev and not tr_maps:
        return []
    out: list[str] = []
    for lit in _charmap_candidates(statements):
        if has_rev:
            r = lit[::-1]
            if _looks_like_command(r):
                out.append(r)
        for mp in tr_maps:
            d = "".join(mp.get(c, c) for c in lit)
            if d != lit and _looks_like_command(d):
                out.append(d)
        if len(out) >= _MAX_BLOBS:
            break
    return out


def _decode_intlist(nums: list[int]) -> str:
    """Decode a list of code points to text IFF it looks like a char-code array
    (>=80% in the printable+ws range) — so a benign int list (versions, ids)
    that happens to decode is gated out before it reaches the junk filter."""
    nums = nums[:512]
    if len(nums) < 3:
        return ""
    printable = sum(1 for n in nums if 9 <= n <= 126)
    if printable / len(nums) < 0.8:
        return ""
    try:
        return "".join(chr(n) for n in nums if 0 <= n < 0x110000)
    except (ValueError, OverflowError):
        return ""


def _decode_interpreter(text: str) -> list[str]:
    """Interpreter-aware de-obfuscation WITHOUT executing anything: assemble the
    string that inline interpreter code (``python -c`` / ``node -e`` / ``php -r``
    / ...) builds from char codes or concatenation, so the hidden command token
    surfaces. Pure string transforms; outputs are junk-filtered by the caller —
    can only ADD a candidate to the search surface, never forge a benign signal."""
    out: list[str] = []
    for rx in (_INT_LIST, _FROMCHARCODE):
        for m in rx.finditer(text):
            s = _decode_intlist([int(x) for x in re.findall(r"\d+", m.group(1))])
            if _looks_like_command(s):
                out.append(s)
            if len(out) >= _MAX_BLOBS:
                return out
    for m in _CHR_CHAIN.finditer(text):
        s = _decode_intlist([int(x) for x in re.findall(r"\d+", m.group(0))])
        if _looks_like_command(s):
            out.append(s)
    # string concatenation: join adjacent quoted literals across + / .
    for m in _CONCAT.finditer(text):
        lits = re.findall(r"(['\"])((?:(?!\1).)*)\1", m.group(0))
        joined = "".join(v for _q, v in lits)
        if _looks_like_command(joined):
            out.append(joined)
        if len(out) >= _MAX_BLOBS:
            break
    return out


def _extract_urls(fragments: list[str]) -> list[str]:
    out: list[str] = []
    for st in fragments:
        try:
            toks = shlex.split(st, posix=True)
        except ValueError:
            toks = st.split()
        if not toks:
            continue
        name = toks[0].rsplit("/", 1)[-1].lower()
        for tok in toks[1:]:
            if _URL_LITERAL.match(tok) or (
                name in {"nc", "netcat"}
                and ("." in tok or ":" in tok)
                and not tok.startswith("-")
            ):
                out.append(tok)
    # also catch a bare URL anywhere (post var-expansion / decode / inside quotes)
    for m in _URL_LITERAL.finditer("\n".join(fragments)):
        u = m.group(0).strip("\"'")
        if u not in out:
            out.append(u)
    return out


def normalize_command(raw: object) -> NormalizedCommand:
    if not isinstance(raw, str) or not raw:
        return NormalizedCommand(raw=raw if isinstance(raw, str) else "")
    try:
        if len(raw) > _MAX_INPUT:
            return NormalizedCommand(raw=raw, text=raw)
        denoised = _strip_noise(raw)
        unescaped = _unescape_inline(denoised)  # ANSI-C / printf escapes, in place
        statements = _split_statements(unescaped)
        vars_ = _collect_vars(statements)
        expanded = [_expand_vars(s, vars_) for s in statements]
        decode_surface = "\n".join([denoised, unescaped, *expanded])
        blobs = _decode_iter(decode_surface)
        # charmap de-obfuscation (rev / tr cipher) — bounded, additive, junk-filtered
        charmap_blobs = _charmap_decode(expanded)
        if charmap_blobs:
            blobs = (blobs + charmap_blobs)[:_MAX_BLOBS]
        # interpreter-aware de-obfuscation (char-codes / concat in python -c etc.)
        interp_blobs = _decode_interpreter(decode_surface)
        if interp_blobs:
            blobs = (blobs + interp_blobs)[:_MAX_BLOBS]
        urls = _extract_urls([*expanded, *blobs])
        text = "\n".join([raw, denoised, unescaped, *expanded, *blobs])
        return NormalizedCommand(
            raw=raw,
            statements=expanded,
            decoded_blobs=blobs,
            text=text,
            urls=urls,
        )
    except Exception:
        return NormalizedCommand(raw=raw, text=raw)
