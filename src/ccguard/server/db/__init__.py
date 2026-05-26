"""Server DB package.

Importing this package eagerly imports ``ccguard.server.db.models`` so every
``SQLModel`` table class is registered with ``SQLModel.metadata`` before any
caller invokes :func:`ccguard.server.db.session.init_db` (which performs
``create_all``).

Phase 4 / Plan 04-01 adds :class:`PolicyApplyEvent` to the registered set —
re-exported here so external callers can rely on ``from ccguard.server.db
import PolicyApplyEvent`` without a deeper import path.
"""
from __future__ import annotations

from ccguard.server.db import models as models  # noqa: F401  (registration)
from ccguard.server.db.models import PolicyApplyEvent

__all__ = ["PolicyApplyEvent", "models"]
