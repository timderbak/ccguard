"""Конфиг агента ccguard: ~/.ccguard/config.yaml + install_salt."""

from __future__ import annotations

import os
import secrets
from pathlib import Path

import yaml
from pydantic import BaseModel, ConfigDict, Field

# Функции путей живут в hot_config (pydantic-free, для горячего пути) и
# реэкспортируются здесь — прежние импорты
# ``from ccguard.agent.config import default_config_dir`` продолжают работать.
from ccguard.agent.hot_config import default_config_dir, default_config_path  # noqa: F401


class ServerSection(BaseModel):
    model_config = ConfigDict(extra="forbid")
    url: str = "http://localhost:8080"
    token: str = ""


class AuditSection(BaseModel):
    model_config = ConfigDict(extra="forbid")
    max_bytes: int = 10 * 1024 * 1024
    backup_count: int = 5


class PolicySection(BaseModel):
    model_config = ConfigDict(extra="forbid")
    cache_path: str = "~/.ccguard/policy.yaml"
    block_fail_mode: str | None = None  # None = взять из самой policy


class SyncSection(BaseModel):
    model_config = ConfigDict(extra="forbid")
    # 15 min matches the daemon's established cadence (DaemonConfig default) and
    # is what the daemon now actually honors + reports in the heartbeat's
    # ``expected_interval_sec``. Was 60 but never wired, so real deployments ran
    # at 15 — this default preserves that observed behavior.
    interval_minutes: int = 15


class AgentConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")

    server: ServerSection = Field(default_factory=ServerSection)
    machine_label: str | None = None
    install_salt: str = ""
    audit: AuditSection = Field(default_factory=AuditSection)
    policy: PolicySection = Field(default_factory=PolicySection)
    sync: SyncSection = Field(default_factory=SyncSection)

    def resolved_cache_path(self) -> Path:
        return Path(os.path.expanduser(self.policy.cache_path))


def load_or_create(path: Path | None = None) -> tuple[AgentConfig, Path]:
    """Загрузить config.yaml; если нет — создать с дефолтами и сгенерированным salt."""
    p = path or default_config_path()
    p.parent.mkdir(parents=True, exist_ok=True)

    if p.exists():
        data = yaml.safe_load(p.read_text()) or {}
        cfg = AgentConfig.model_validate(data)
        if not cfg.install_salt:
            cfg.install_salt = secrets.token_hex(32)
            save(cfg, p)
        return cfg, p

    cfg = AgentConfig(install_salt=secrets.token_hex(32))
    save(cfg, p)
    return cfg, p


def save(cfg: AgentConfig, path: Path) -> None:
    """Сохранить конфиг атомарно (через tmp + rename)."""
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_text(yaml.safe_dump(cfg.model_dump(mode="json"), sort_keys=False))
    tmp.replace(path)
    try:
        os.chmod(path, 0o600)  # секретный токен внутри
    except OSError:
        pass
