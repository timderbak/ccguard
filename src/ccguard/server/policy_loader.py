"""PolicyLoader: reads current policy from DB, bootstraps from YAML on empty DB."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml
from sqlmodel import Session

from ccguard.schemas import Policy
from ccguard.server.db.models import PolicyVersion
from ccguard.server.services.policy_service import get_current_published


class PolicyLoader:
    def __init__(self, *, file_path: Path, engine: Any) -> None:
        self.file_path = file_path
        self.engine = engine

    def load_with_etag(self, session: Session) -> tuple[Policy, str]:
        current = get_current_published(session)
        if current is None:
            current = self._bootstrap_from_file(session)
        policy = Policy.model_validate(yaml.safe_load(current.yaml_text))
        return policy, f'"rev-{current.revision}"'

    def _bootstrap_from_file(self, session: Session) -> PolicyVersion:
        if not self.file_path.exists():
            raise FileNotFoundError(
                f"no policy in DB and bootstrap file missing: {self.file_path}"
            )
        text = self.file_path.read_text()
        data = yaml.safe_load(text)
        revision = int(data.get("meta", {}).get("revision", 1))
        row = PolicyVersion(
            revision=revision,
            status="published",
            yaml_text=text,
            created_by="bootstrap",
        )
        session.add(row)
        session.commit()
        session.refresh(row)
        return row
