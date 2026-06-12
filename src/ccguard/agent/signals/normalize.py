"""Shared, bounded, fail-open command normalizer (Phase 1 / P1).

De-obfuscates a bash command BEFORE matchers (enforce + signal-extraction) run,
so encoded/indirected payloads are matched on clean text instead of slipping
through raw-string regexes. Pure: no I/O, no shell execution, never raises.
"""
from __future__ import annotations

import base64
import binascii
import re
import shlex
from dataclasses import dataclass, field

# Hard bounds — normalization is a small slice of the <100ms PreToolUse budget.
_MAX_INPUT = 64_000          # chars; larger → fail-open to raw
_MAX_BLOBS = 8               # base64/hex blobs decoded per command
_MAX_VARS = 32               # simple var assignments tracked

_B64_TOKEN = re.compile(r"[A-Za-z0-9+/]{16,}={0,2}")
_HEX_TOKEN = re.compile(r"(?:\\x[0-9a-fA-F]{2}){6,}|\b[0-9a-fA-F]{16,}\b")
_ASSIGN = re.compile(r"^([A-Za-z_][A-Za-z0-9_]*)=(.+)$")
_URL_LITERAL = re.compile(r"https?://\S+", re.IGNORECASE)


@dataclass(frozen=True)
class NormalizedCommand:
    raw: str
    statements: list[str] = field(default_factory=list)
    decoded_blobs: list[str] = field(default_factory=list)
    text: str = ""
    urls: list[str] = field(default_factory=list)


def _strip_noise(s: str) -> str:
    s = s.replace("${IFS}", " ").replace("$IFS", " ")
    # collapse intra-token quote noise: c""url -> curl, c''url -> curl
    s = re.sub(r"(\w)['\"]{2,}(\w)", r"\1\2", s)
    s = re.sub(r"(\w)['\"](\w)", r"\1\2", s)
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


def _collect_vars(statements: list[str]) -> dict[str, str]:
    out: dict[str, str] = {}
    for st in statements:
        m = _ASSIGN.match(st.strip())
        if m and len(out) < _MAX_VARS:
            out[m.group(1)] = m.group(2).strip().strip("'\"")
    return out


def _expand_vars(text: str, vars_: dict[str, str]) -> str:
    if not vars_:
        return text

    def repl(m: re.Match[str]) -> str:
        name = m.group(1) or m.group(2)
        return vars_.get(name, m.group(0))

    return re.sub(r"\$\{([A-Za-z_]\w*)\}|\$([A-Za-z_]\w*)", repl, text)


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


def _decode_blobs(text: str) -> list[str]:
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


def _extract_urls(statements: list[str]) -> list[str]:
    out: list[str] = []
    for st in statements:
        try:
            toks = shlex.split(st, posix=True)
        except ValueError:
            toks = st.split()
        if not toks:
            continue
        name = toks[0].rsplit("/", 1)[-1].lower()
        for tok in toks[1:]:
            if _URL_LITERAL.match(tok):
                out.append(tok)
            elif (
                name in {"nc", "netcat"}
                and ("." in tok or ":" in tok)
                and not tok.startswith("-")
            ):
                out.append(tok)
    # also catch a bare URL anywhere (post var-expansion / inside quotes)
    for m in _URL_LITERAL.finditer("\n".join(statements)):
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
        statements = _split_statements(denoised)
        vars_ = _collect_vars(statements)
        expanded = [_expand_vars(s, vars_) for s in statements]
        decoded = _decode_blobs(denoised)
        urls = _extract_urls(expanded)
        text = "\n".join([raw, denoised, *expanded, *decoded])
        return NormalizedCommand(
            raw=raw,
            statements=expanded,
            decoded_blobs=decoded,
            text=text,
            urls=urls,
        )
    except Exception:
        return NormalizedCommand(raw=raw, text=raw)
