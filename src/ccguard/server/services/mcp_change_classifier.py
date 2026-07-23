"""Classify an MCP definition change — is it a routine update or a rug-pull?

The naïve rug-pull detector fires on ANY ``definition_hash`` change. But MCP
servers legitimately update every day: a developer bumps ``foo@1.2.3`` → ``1.3.0``
and the hash moves. Flagging that at ``warn`` is exactly the false-positive noise
that makes the product un-shippable ("сильно фалзит").

This classifier looks at the actual (secret-masked) definition text — old vs new —
and decides WHAT KIND of change it is, so the baseline service can emit an honest
severity instead of a blanket ``warn``:

* **version_bump** — a semver pin moved forward and nothing else changed
  (``foo@1.2.3`` → ``foo@1.3.0``). The operator pinned a version; it advanced.
  → **info** (an expected update, not a finding-worthy event).
* **pin_dropped** — a semver pin became a floating tag (``foo@1.2.3`` → ``foo@latest``).
  Pinning is the defence against silent supply-chain swaps; losing it is suspicious.
  → **warn**.
* **digest_change** — a content digest (``@sha256:…``) moved. Digest pinning means
  "this exact content"; a silent digest change is the textbook mutable-reference
  rug-pull (the tj-actions lesson). → **critical**.
* **target_shift** — the endpoint host changed, or the command now points at a
  suspicious local target (``/tmp``, an absolute path, a raw IP, non-TLS ``http://``).
  A benign version bump never does this. → **critical**.
* **opaque** — a real command/args/url change we can't confidently bucket (or no
  stored old definition to compare against). → **warn** (the cautious default,
  preserving the pre-classifier behaviour).

The classifier is PURE and deterministic (offline-testable). An optional
:data:`Corroborator` seam lets a caller consult upstream provenance (does an npm
release / changelog exist for this change?) to de-escalate an ``opaque`` change it
can vouch for — the "сходить в репозиторий и посмотреть changelog" idea. The
concrete registry provider is injected (kept out of this pure module).
"""
from __future__ import annotations

import re
from collections.abc import Callable
from dataclasses import dataclass

# --- Verdict ---------------------------------------------------------------


@dataclass(frozen=True)
class ChangeVerdict:
    """The classification of one definition change.

    ``kind`` is a stable slug for the payload/tests; ``severity`` is the
    info/warn/critical band the baseline service should emit at.
    """

    kind: str
    severity: str
    rationale: str


# A corroborator answers "is this change backed by upstream provenance?" —
# True = a matching release/changelog exists (de-escalate), False = a silent
# change with no upstream record (keep/escalate), None = unknown (leave as-is).
Corroborator = Callable[[str, str], "bool | None"]


# --- Token analysis --------------------------------------------------------

# A semantic-version pin after @ / == / : — ``@1.2.3``, ``==1.2``, ``:v1.2.3``.
_SEMVER = re.compile(r"(?:@|==|:)v?\d+(?:\.\d+){0,3}(?:[-+.][0-9A-Za-z.]+)?")
# A floating/mutable tag — no fixed content behind it.
_FLOATING = re.compile(
    r"@(?:latest|next|beta|alpha|canary|dev|nightly|edge|rc|main|master|head)\b"
    r"|:latest\b",
    re.IGNORECASE,
)
# A content digest pin — ``@sha256:<hex>``.
_DIGEST = re.compile(r"@sha256:[0-9a-f]{7,64}", re.IGNORECASE)
# A raw IPv4 literal (host that isn't a name — common in ad-hoc C2 endpoints).
_RAW_IP = re.compile(r"\b\d{1,3}(?:\.\d{1,3}){3}\b")
# Suspicious command target a benign npx/uvx/docker launch never uses. Kept
# NARROW on purpose (the classifier's job is fewer false criticals): world-
# writable scratch dirs an attacker stages in, and a non-TLS endpoint. Hidden
# home paths are deliberately excluded — they false-positive on npm/uv caches.
_SUSPICIOUS_TARGET = re.compile(
    r"(?:^|\s)(?:/tmp/|/var/tmp/|/dev/shm/|/private/tmp/|/private/var/tmp/)"  # scratch dirs
    r"|\bhttp://"                                                             # non-TLS endpoint
)
_URL_IN_DEF = re.compile(r"\|\s*(\S+)\s*$")  # trailing ``| <url>`` of a def text


def _host_of(def_text: str) -> str | None:
    m = _URL_IN_DEF.search(def_text)
    if not m:
        return None
    url = m.group(1)
    hm = re.search(r"https?://([^/\s:]+)", url)
    return hm.group(1).lower() if hm else None


@dataclass(frozen=True)
class _Analysis:
    has_semver: bool
    has_floating: bool
    digests: tuple[str, ...]
    host: str | None
    suspicious_target: str | None


def _analyze(def_text: str) -> _Analysis:
    digests = tuple(sorted(m.group(0).lower() for m in _DIGEST.finditer(def_text)))
    susp = _SUSPICIOUS_TARGET.search(def_text)
    susp_token = susp.group(0).strip() if susp else None
    if susp_token is None:
        ip = _RAW_IP.search(def_text)
        # a raw IP is only suspicious in the URL/host position, not inside a version
        if ip and (_host_of(def_text) and _RAW_IP.search(_host_of(def_text) or "")):
            susp_token = ip.group(0)
    return _Analysis(
        has_semver=bool(_SEMVER.search(def_text)),
        has_floating=bool(_FLOATING.search(def_text)),
        digests=digests,
        host=_host_of(def_text),
        suspicious_target=susp_token,
    )


def _strip_semver_and_digest(def_text: str) -> str:
    """Blank out version + digest tokens so two defs that differ ONLY in their
    pinned version compare equal (the pure-version-bump test)."""
    t = _DIGEST.sub("@<DIGEST>", def_text)
    t = _SEMVER.sub("<VER>", t)
    return t


# --- Public API ------------------------------------------------------------


def classify_definition_change(
    old_def: str | None,
    new_def: str | None,
    *,
    corroborator: Corroborator | None = None,
) -> ChangeVerdict:
    """Classify a ``command args | url`` definition change (old → new).

    ``old_def`` is None for pre-classifier baselines / v0.1 agents → we can't
    compare, so it degrades to ``opaque``/``warn`` (the old blanket behaviour).
    """
    if not old_def or not new_def:
        return ChangeVerdict("opaque", "warn", "нет сохранённого старого определения для сравнения")
    if old_def == new_def:
        # Shouldn't happen (caller diffs hashes first) but stay total.
        return ChangeVerdict("noop", "info", "определение не изменилось")

    old, new = _analyze(old_def), _analyze(new_def)

    # 1. Endpoint host moved (http/sse) — a benign bump never repoints the server.
    if old.host and new.host and old.host != new.host:
        return ChangeVerdict(
            "target_shift", "critical", f"endpoint сменил хост: {old.host} → {new.host}"
        )

    # 2. Command now points at a suspicious local target (temp/hidden/raw-IP/non-TLS).
    if new.suspicious_target and new.suspicious_target != old.suspicious_target:
        return ChangeVerdict(
            "target_shift",
            "critical",
            f"команда указывает на подозрительную цель: {new.suspicious_target}",
        )

    # 3. Pinned content digest moved — pin-by-digest means "this exact content".
    if old.digests and new.digests and set(old.digests) != set(new.digests):
        return ChangeVerdict(
            "digest_change",
            "critical",
            "закреплённый digest (sha256) изменился — классическая тихая подмена по mutable-ссылке",
        )

    # 4. Version un-pinned: was semver, now floating/@latest — защита снята.
    if old.has_semver and new.has_floating and not new.has_semver:
        return ChangeVerdict(
            "pin_dropped",
            "warn",
            "версия разфиксирована (→ floating/@latest) — теряется защита от тихой подмены",
        )

    # 5. Pure version bump: strip versions/digests and the rest is identical →
    #    the ONLY change is a pinned semver moving. This is the routine update
    #    that must NOT false-positive.
    if (
        old.has_semver
        and new.has_semver
        and not old.has_floating
        and not new.has_floating
        and _strip_semver_and_digest(old_def) == _strip_semver_and_digest(new_def)
    ):
        return ChangeVerdict("version_bump", "info", "обновление версии по пину — ожидаемое обновление")

    # 6. Unclassified real change. Optionally consult upstream provenance before
    #    settling on the cautious default.
    if corroborator is not None:
        try:
            verdict = corroborator(old_def, new_def)
        except Exception:  # noqa: BLE001 — corroboration is best-effort
            verdict = None
        if verdict is True:
            return ChangeVerdict(
                "corroborated_update",
                "info",
                "изменение подтверждено upstream-релизом/changelog — ожидаемое обновление",
            )
        if verdict is False:
            return ChangeVerdict(
                "uncorroborated_change",
                "critical",
                "изменение без соответствующего upstream-релиза — признак тихой подмены",
            )

    return ChangeVerdict(
        "opaque", "warn", "изменение command/args/url, не распознано как обычный bump версии"
    )
