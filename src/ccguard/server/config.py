"""Конфиг сервера: токены, путь к policy, БД."""

from __future__ import annotations

import os
from pathlib import Path

import yaml
from pydantic import BaseModel, ConfigDict, Field


class TokenEntry(BaseModel):
    model_config = ConfigDict(extra="forbid")
    value: str
    label: str = "unnamed"


class ServerConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")

    tokens: list[TokenEntry] = Field(default_factory=list)
    policy_path: str = "/etc/ccguard/server_policy.yaml"
    db_url: str = "sqlite:///./ccguard.db"
    host: str = "0.0.0.0"
    port: int = 8080
    log_level: str = "INFO"

    @classmethod
    def load(cls, path: str | Path | None = None) -> ServerConfig:
        """Загрузить конфиг. Приоритет: явный path → CCGUARD_SERVER_CONFIG → дефолты."""
        cfg_path = (
            Path(path)
            if path
            else Path(os.environ.get("CCGUARD_SERVER_CONFIG", "/etc/ccguard/server_config.yaml"))
        )
        if cfg_path.exists():
            data = yaml.safe_load(cfg_path.read_text()) or {}
            return cls.model_validate(data)
        # Без конфига работаем на дефолтах + токены из env (для dev/docker).
        env_tokens = os.environ.get("CCGUARD_TOKENS", "")
        tokens = [TokenEntry(value=t.strip()) for t in env_tokens.split(",") if t.strip()]
        return cls(
            tokens=tokens,
            policy_path=os.environ.get("CCGUARD_POLICY_PATH", cls.model_fields["policy_path"].default),
            db_url=os.environ.get("CCGUARD_DB_URL", cls.model_fields["db_url"].default),
            host=os.environ.get("CCGUARD_HOST", cls.model_fields["host"].default),
            port=int(os.environ.get("CCGUARD_PORT", cls.model_fields["port"].default)),
            log_level=os.environ.get("CCGUARD_LOG_LEVEL", cls.model_fields["log_level"].default),
        )

    def is_token_valid(self, token: str) -> bool:
        return any(t.value == token for t in self.tokens)
