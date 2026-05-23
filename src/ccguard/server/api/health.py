"""Health endpoint. Не требует аутентификации."""

from __future__ import annotations

from fastapi import APIRouter, Depends
from sqlmodel import Session, select

from ccguard.server.api.deps import get_policy_loader, get_session
from ccguard.server.db.models import Machine
from ccguard.server.policy_loader import PolicyLoader

router = APIRouter()


@router.get("/health")
def health(
    session: Session = Depends(get_session),
    loader: PolicyLoader = Depends(get_policy_loader),
) -> dict[str, object]:
    db_ok = True
    try:
        session.exec(select(Machine).limit(1)).first()
    except Exception:
        db_ok = False
    try:
        policy_revision: int | None = loader.get().policy.meta.revision
    except Exception:
        policy_revision = None
    return {
        "status": "ok",
        "policy_revision": policy_revision,
        "db": "ok" if db_ok else "error",
    }
