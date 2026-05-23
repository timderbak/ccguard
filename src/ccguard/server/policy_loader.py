"""Загрузка policy.yaml с инвалидацией по mtime."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

import yaml

from ccguard.schemas import Policy


@dataclass
class CachedPolicy:
    policy: Policy
    mtime: float
    etag: str


class PolicyLoader:
    """Кэширующий загрузчик. Перечитывает файл при изменении mtime."""

    def __init__(self, path: str | Path) -> None:
        self._path = Path(path)
        self._cache: CachedPolicy | None = None

    def get(self) -> CachedPolicy:
        if not self._path.exists():
            raise FileNotFoundError(f"policy file not found: {self._path}")
        mtime = self._path.stat().st_mtime
        if self._cache is not None and self._cache.mtime == mtime:
            return self._cache
        data = yaml.safe_load(self._path.read_text()) or {}
        policy = Policy.model_validate(data)
        etag = f'"rev-{policy.meta.revision}"'
        self._cache = CachedPolicy(policy=policy, mtime=mtime, etag=etag)
        return self._cache
