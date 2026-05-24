"""CSRF tokens: itsdangerous-signed strings tied to session id."""
from __future__ import annotations

from itsdangerous import BadSignature, TimestampSigner


def generate_csrf_token(*, secret: str, session_id: str) -> str:
    return TimestampSigner(secret).sign(session_id).decode()


def verify_csrf_token(
    token: str,
    *,
    secret: str,
    session_id: str,
    max_age_sec: int = 86400,
) -> bool:
    if not token:
        return False
    try:
        unsigned = TimestampSigner(secret).unsign(token, max_age=max_age_sec).decode()
    except (BadSignature, ValueError):
        return False
    return unsigned == session_id
