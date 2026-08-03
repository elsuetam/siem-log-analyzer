"""Configurações centrais da aplicação, carregadas de variáveis de ambiente."""

from __future__ import annotations

from functools import lru_cache
from pathlib import Path

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Configurações da aplicação carregadas do ambiente (.env)."""

    model_config = SettingsConfigDict(env_prefix="SIEM_", env_file=".env", extra="ignore")

    raw_logs_dir: Path = Field(default=Path("data/raw_logs"))
    output_dir: Path = Field(default=Path("output"))
    log_level: str = Field(default="INFO")


@lru_cache
def get_settings() -> Settings:
    """Retorna a instância única (cacheada) das configurações da aplicação."""
    return Settings()