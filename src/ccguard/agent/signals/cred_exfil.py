"""Single-command credential-exfil detector (hard-deny tier).

The flagship AI-agent attack: read a credential store AND send it out in ONE
command. This is FP-safe by construction — it fires only when the cred file is
the EGRESS PAYLOAD (piped into / uploaded by / substituted into a network call),
not merely co-located with a curl. There is no legitimate reason to POST your
``~/.aws/credentials`` to a network destination, so this is safe to hard-block.

Used by enforce (block-before-it-leaves) and shareable with the audit path.
"""
from __future__ import annotations

import re

# Credential-store path/file markers (file-based; env-var exfil is a separate,
# FP-riskier vector deliberately left to the correlation engines, not hard-block).
_CRED = (
    r"(?:\.aws/credentials|\.aws/config|/\.ssh/id_[a-z0-9_]+|\bid_rsa\b|\bid_ed25519\b"
    r"|\.ssh/identity|\.env(?:\.[\w.-]+)?\b|\.netrc\b|\.npmrc\b|\.pypirc\b|\.git-credentials\b"
    r"|\.pgpass\b|\.docker/config\.json|\.kube/config|\.gnupg/|application_default_credentials\.json"
    r"|service[_-]?account[\w.-]*\.json|secrets?\.(?:ya?ml|json|env))"
)

_CRED_EXFIL = re.compile(
    # (A) curl/wget upload flag whose argument is a cred file
    r"\b(?:curl|wget|http|https|httpie)\b[^\n|;&]*"
    r"(?:-d|--data(?:-binary|-raw|-urlencode)?|-T|--upload-file|-F|--form)\s*[@=]?\s*['\"]?[^\n|;&'\"]*" + _CRED
    # (B) read cred, piped into a network sender
    + r"|\b(?:cat|head|tail|base64|gpg|openssl|xxd)\b[^\n|]*" + _CRED
    + r"[^\n]*\|\s*(?:curl|wget|nc\b|ncat\b|socat\b|https?\b|python[0-9.]*\b|perl\b|ruby\b|requests\.|httpx\.)"
    # (C) command-substitution of a cred read into a network call
    + r"|\b(?:curl|wget|nc|ncat|https?)\b[^\n]*\$\(\s*(?:cat|head|base64|<)\s*[^\n)]*" + _CRED
    # (D) python inline requests/httpx post with open(credfile)
    + r"|(?:requests|httpx)\.(?:post|put|patch)\([^\n]*open\(\s*['\"]?[^\n]*" + _CRED,
    re.IGNORECASE,
)


def detect_cred_exfil(text: str) -> bool:
    """True iff ``text`` reads a credential store AND sends it out in one command
    (the cred file is the egress payload). FP-safe — never matches a benign
    co-occurrence of a cred path and an unrelated network call."""
    return bool(_CRED_EXFIL.search(text))
