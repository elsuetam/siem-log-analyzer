"""Testes unitários para o módulo de configurações (siem.config.settings)."""

from __future__ import annotations

from pathlib import Path

import pytest
from pydantic import ValidationError

from siem.config.settings import Settings


def test_settings_default_values() -> None:
    """Garante que as configurações carregam com valores padrão sensatos."""
    settings = Settings(_env_file=None)

    assert settings.raw_logs_dir == Path("data/raw_logs")
    assert settings.output_dir == Path("output")
    assert settings.log_level == "INFO"
    assert settings.brute_force_attempts_threshold == 5
    assert settings.brute_force_window_seconds == 60


def test_settings_log_level_is_normalized_to_uppercase() -> None:
    """Garante que log_level informado em minúsculas é normalizado."""
    settings = Settings(_env_file=None, log_level="debug")

    assert settings.log_level == "DEBUG"


def test_settings_invalid_log_level_raises_error() -> None:
    """Garante que um log_level inválido é rejeitado na validação."""
    with pytest.raises(ValidationError):
        Settings(_env_file=None, log_level="NOT_A_LEVEL")


def test_settings_brute_force_threshold_must_be_positive() -> None:
    """Garante que thresholds numéricos não aceitam valores menores que 1."""
    with pytest.raises(ValidationError):
        Settings(_env_file=None, brute_force_attempts_threshold=0)


def test_ensure_directories_creates_missing_paths(tmp_path: Path) -> None:
    """Garante que ensure_directories_exist() cria os diretórios configurados."""
    settings = Settings(
        _env_file=None,
        raw_logs_dir=tmp_path / "raw_logs",
        processed_dir=tmp_path / "processed",
        output_dir=tmp_path / "output",
        reports_dir=tmp_path / "output" / "reports",
        dashboards_dir=tmp_path / "output" / "dashboards",
    )

    settings.ensure_directories_exist()

    assert settings.raw_logs_dir.exists()
    assert settings.processed_dir.exists()
    assert settings.reports_dir.exists()
    assert settings.dashboards_dir.exists()