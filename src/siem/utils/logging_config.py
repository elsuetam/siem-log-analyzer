"""Configuração centralizada de logging da aplicação."""

from __future__ import annotations

import logging
import sys

from siem.config.settings import get_settings


def setup_logging() -> None:
    """Configura o logging raiz da aplicação com base nas configurações do sistema."""
    settings = get_settings()

    logging.basicConfig(
        level=getattr(logging, settings.log_level.upper(), logging.INFO),
        format="%(asctime)s | %(levelname)-8s | %(name)s | %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
        stream=sys.stdout,
    )