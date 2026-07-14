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

# --- Total, irreversible host destruction (hard-deny tier) ------------------
# The NARROW subset of destruction that is never legitimate from an AI agent and
# is blocked out of the box even in observe mode (like credential-exfil and
# EDR-kill): a recursive delete of the filesystem/home ROOT itself. Everything
# else — a sensitive-path delete (`rm -rf /etc/...`), and ALL raw-disk wipes
# (mkfs/wipefs/dd: legitimate in too many contexts and trivially bypassed) —
# stays out of hard-deny (policy tier / the impact.disk_wipe DETECT signal).

# Bare filesystem root or home root — `rm -rf /`, `/`+glob/alias, `~`, `$HOME`.
# The root arm accepts only slash/dot/star chars after the leading `/` so path
# ALIASES that resolve to root (`/`, `//`, `/.`, `/..`, `/*`, `/*/`) all match,
# while any real component (`/etc`, `/tmp/build`) does NOT — ordinary deletes
# stay out. Home arms cover `~[/][*]` and `$HOME` / `${HOME}` with an optional
# trailing slash/glob.
_ROOT_HOME_TARGET_RE = re.compile(r"^(?:/[/.*]*|~/?\*?|\$\{?HOME\}?/?\*?)$")


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


def _cmd_basename(tok: str) -> str:
    """Command name of a token, ignoring a path prefix, a leading escape
    backslash and surrounding quotes: `/bin/rm`, `\\rm`, `"rm"` → ``rm``."""
    return tok.rsplit("/", 1)[-1].lstrip("\\").strip("\"'")


def _is_total_fs_wipe(command: str) -> bool:
    """Recursive ``rm`` of the filesystem/home ROOT (`rm -rf /`, `rm -r ~`,
    `$HOME`) or any ``rm`` carrying ``--no-preserve-root`` (which only ever
    targets ``/``). Recursion is what makes a directory target catastrophic;
    ``-f`` only suppresses prompts, so a force-only `rm -f /` (a harmless no-op)
    is intentionally NOT caught. A subpath target keeps it out — that is ordinary
    work (`rm -rf node_modules`, `rm -rf ~/.cache/pip`)."""
    for seg in _SEGMENT_SPLIT.split(command):
        toks = seg.split()
        # `find <root> ... -exec rm -rf {} +` / `... -delete`: the bare-root token
        # is find's SEARCH ROOT, not rm's target (rm acts on the matched {}). Never
        # hard-block here — mass-deletion via find stays in the policy tier.
        if any(_cmd_basename(t) == "find" for t in toks):
            continue
        if not any(_cmd_basename(t) == "rm" for t in toks):
            continue
        longs = {t.lower() for t in toks if t.startswith("--")}
        # `--no-preserve-root` has no legitimate use — its only purpose is to let
        # `rm` delete `/`. Presence alone is a definitive total-wipe signal.
        if "--no-preserve-root" in longs:
            return True
        shortflags = "".join(
            t[1:] for t in toks if t.startswith("-") and not t.startswith("--")
        ).lower()
        recursive = "r" in shortflags or "--recursive" in longs
        if not recursive:
            continue
        for t in toks:
            if t.startswith("-") or _cmd_basename(t) in ("rm", "sudo"):
                continue
            # a single-quoted `~`/`$HOME` is a LITERAL filename (shell does not
            # expand inside single quotes), not the home directory → not a wipe.
            single_quoted = len(t) >= 2 and t[0] == "'" and t[-1] == "'"
            bare = t.strip("\"'")
            if single_quoted and bare in ("~", "$HOME", "${HOME}"):
                continue
            if _ROOT_HOME_TARGET_RE.match(bare):
                return True
    return False


def detect_total_destruction(command: str) -> str | None:
    """Category for a command that IRREVERSIBLY destroys the whole host, else None.

    Currently only ``"fs_wipe"`` — a recursive delete of the filesystem/home
    ROOT (`rm -rf /`, `rm -r ~`, `--no-preserve-root`). This is the narrow,
    never-legitimate, zero-FP subset the enforce hard-deny tier blocks even in
    observe mode. A sensitive-path delete (`rm -rf /etc/...`) stays in the policy
    tier. Raw-disk wipes (mkfs/wipefs/dd) are deliberately NOT here: formatting a
    disk is legitimate in too many contexts (cloud volumes, USB/SD, CI/VM) and is
    trivially bypassed, so it is DETECT-only (the ``impact.disk_wipe`` audit
    signal), never a hard-deny. Never raises.
    """
    try:
        if not isinstance(command, str) or not command:
            return None
        if _is_total_fs_wipe(command):
            return "fs_wipe"
        return None
    except Exception:  # noqa: BLE001 — detection must never break the hot path
        return None
