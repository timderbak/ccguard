"""Базовый класс схем с общими настройками."""

from __future__ import annotations

from pydantic import BaseModel, ConfigDict


class SchemaBase(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
        str_strip_whitespace=True,
        frozen=False,
    )
