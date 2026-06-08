"""Destructive-action detection (ТЗ-IMPACT).

Detect data-destruction — deletion / DB-destruction / overwrite — but ONLY when
it targets a DANGEROUS path/object, NOT an allowlisted safe target. A developer
runs ``rm -rf node_modules`` and ``DROP TABLE test_db`` constantly: those are
normal work, not impact. Destruction = a destructive verb × a sensitive target
(home dotfiles holding secrets, system dirs, a non-test DB).

Single source of truth shared by BOTH detection paths so block (PREV) and
signal (DETECT) never diverge:
  * the audit-signal extractor emits ``impact.{delete,db,overwrite}`` → feeds
    the ТЗ-09 chain engine (revives ``poison_to_destructive``) + DETECT;
  * the enforce path turns the same category into a deny (PREV) / finding.

Privacy: the entry point takes the command string (which the caller already
holds) and returns only a CATEGORY string — never the path/command/target.

This is a vetted STARTER set (like the chain scenarios): precise over complete,
to keep observe-mode false positives near zero. The allowlist will be refined on
real traffic. Git-destruction (force-push/reset) is deliberately excluded
(too often legitimate → FP-prone).
"""
from __future__ import annotations

import re

# --- Allowlist: destroying these is normal dev work, never "impact" ---------
# Mirrors extractor._CACHE_WRITE_COMPONENTS (build/package noise) + build output
# dirs + virtualenvs. Matched component-wise on the (lowercased) path.
SAFE_PATH_COMPONENTS: frozenset[str] = frozenset(
    {
        "node_modules", "dist", "build", ".next", "out", "target", "coverage",
        ".cache", ".pytest_cache", "__pycache__", ".mypy_cache", ".tox",
        ".npm", ".cargo", "site-packages", ".venv", "venv", ".gradle",
        ".parcel-cache", ".turbo", ".svelte-kit", ".nuxt", "bin/debug", "obj",
    }
)
_SAFE_PATH_SUBSTR = ("/tmp/", "/var/tmp/", "/private/tmp/")

# --- Sensitive targets a destructive op must never hit silently -------------
_SENSITIVE_TARGET_RES: tuple[re.Pattern[str], ...] = (
    # bare home or filesystem root: `rm -rf /`, `rm -rf ~`, `rm -rf $HOME`
    re.compile(r"^(/|~|\$HOME|\$\{HOME\})/?$"),
    # home dotdirs holding secrets / config
    re.compile(r"(~|\$HOME|\$\{HOME\}|/home/[^/]+|/root|/users/[^/]+)?/?"
               r"\.(ssh|aws|gnupg|gpg|kube|config|docker|azure|gcloud|netrc)\b", re.I),
    # system roots
    re.compile(r"^/(etc|usr|var|bin|sbin|lib|lib64|boot|opt|srv|sys|root)(/|$)", re.I),
)
# Secret files for overwrite/redirection detection.
_SENSITIVE_FILE_RES: tuple[re.Pattern[str], ...] = (
    re.compile(r"\.ssh/(id_\w+|authorized_keys|known_hosts|config)", re.I),
    re.compile(r"\.aws/(credentials|config)", re.I),
    re.compile(r"\.(gnupg|gpg)/", re.I),
    re.compile(r"\.kube/config", re.I),
    re.compile(r"\.netrc\b", re.I),
)

_SEGMENT_SPLIT = re.compile(r"[;&|\n]+")


def _components(path: str) -> set[str]:
    return {c for c in re.split(r"[\\/]", path.lower()) if c not in ("", ".", "..")}


def _is_safe_target(path: str) -> bool:
    p = path.lower()
    if any(sub in p for sub in _SAFE_PATH_SUBSTR) or p.startswith("/tmp/"):
        return True
    return bool(_components(path) & SAFE_PATH_COMPONENTS)


def _is_sensitive_target(path: str) -> bool:
    return any(r.search(path) for r in _SENSITIVE_TARGET_RES)


def _is_sensitive_file(path: str) -> bool:
    return any(r.search(path) for r in _SENSITIVE_FILE_RES) or _is_sensitive_target(path)


def _is_safe_db_name(name: str) -> bool:
    n = name.lower().strip("`\"'").split(".")[-1]  # drop schema qualifier
    parts = n.split("_")
    return (
        "test" in parts or "tmp" in parts or "scratch" in parts
        or "fixture" in parts or "sandbox" in parts or "fixtures" in parts
        or n.startswith("test") or n.endswith("test")
    )


# --- category detectors -----------------------------------------------------
def _is_destructive_delete(command: str) -> bool:
    for seg in _SEGMENT_SPLIT.split(command):
        toks = seg.split()
        if not toks:
            continue
        # find -delete on a sensitive path
        if "find" in toks and "-delete" in toks:
            paths = [t for t in toks if not t.startswith("-") and t not in ("find",)]
            if any(_is_sensitive_target(p) and not _is_safe_target(p) for p in paths):
                return True
        if "rm" not in toks and "shred" not in toks:
            continue
        verb = "rm" if "rm" in toks else "shred"
        flags = "".join(t[1:] for t in toks if t.startswith("-") and not t.startswith("--"))
        paths = [t for t in toks if not t.startswith("-") and t not in ("rm", "shred", "sudo", "find")]
        if verb == "rm":
            recursive_force = "r" in flags.lower() and "f" in flags.lower()
            force_only = "f" in flags.lower()
            for p in paths:
                if _is_safe_target(p):
                    continue
                if recursive_force and _is_sensitive_target(p):
                    return True
                if force_only and _is_sensitive_file(p):  # rm -f ~/.ssh/id_rsa
                    return True
        else:  # shred
            if any(_is_sensitive_file(p) and not _is_safe_target(p) for p in paths):
                return True
    return False


_DROP_RE = re.compile(
    r"\b(?:DROP\s+(?:TABLE|DATABASE|SCHEMA)|TRUNCATE(?:\s+TABLE)?)\s+"
    r"(?:IF\s+EXISTS\s+)?[`\"']?([\w.]+)",
    re.I,
)
# DELETE FROM <name> with NO WHERE clause (ends or chains right after the table).
_DELETE_NO_WHERE_RE = re.compile(
    r"\bDELETE\s+FROM\s+[`\"']?([\w.]+)[`\"']?\s*(?:;|$)", re.I
)


def _is_destructive_db(command: str) -> bool:
    matches = [*_DROP_RE.finditer(command), *_DELETE_NO_WHERE_RE.finditer(command)]
    return any(not _is_safe_db_name(m.group(1)) for m in matches)


_REDIR_RE = re.compile(r">>?\s*([^\s;&|>]+)")
_DD_RE = re.compile(r"\bdd\b[^\n;|&]*?\bof=([^\s;&|]+)", re.I)
_CHRECURSIVE_RE = re.compile(r"\b(chmod|chown)\b([^\n;|&]*)", re.I)


def _is_destructive_overwrite(command: str) -> bool:
    # redirection that clobbers a secret file: `> ~/.aws/credentials`
    for m in _REDIR_RE.finditer(command):
        target = m.group(1)
        if _is_sensitive_file(target) and not _is_safe_target(target):
            return True
    # dd writing to a device or sensitive target
    for m in _DD_RE.finditer(command):
        target = m.group(1)
        if (target.startswith("/dev/") or _is_sensitive_file(target)) and not _is_safe_target(target):
            return True
    # recursive chmod/chown over a sensitive/system path
    for m in _CHRECURSIVE_RE.finditer(command):
        rest = m.group(2)
        if not re.search(r"(^|\s)-\S*[rR]", rest):
            continue
        paths = [t for t in rest.split() if not t.startswith("-")]
        # chmod MODE PATH... / chown OWNER PATH... → skip the first arg
        for p in paths[1:]:
            if _is_sensitive_target(p) and not _is_safe_target(p):
                return True
    return False


def detect_destructive(command: str) -> str | None:
    """Return the destructive category for a Bash command, or None.

    ``"delete"`` | ``"db"`` | ``"overwrite"`` when the command destroys a
    SENSITIVE target not on the safe allowlist; ``None`` for normal dev work
    (``rm -rf node_modules``, ``DROP TABLE test_db``, ``> dist/bundle.js``) and
    non-destructive commands. Never raises.
    """
    try:
        if not isinstance(command, str) or not command:
            return None
        if _is_destructive_delete(command):
            return "delete"
        if _is_destructive_overwrite(command):
            return "overwrite"
        if _is_destructive_db(command):
            return "db"
        return None
    except Exception:  # noqa: BLE001 — detection must never break the hot path
        return None
