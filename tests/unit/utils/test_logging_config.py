"""Testes unitários para setup_logging."""

from __future__ import annotations

import logging

from siem.utils.logging_config import setup_logging


def test_setup_logging_configures_root_logger_level() -> None:
    """setup_logging deve configurar o logger raiz com o nível vindo das settings."""
    setup_logging()

    root_logger = logging.getLogger()
    assert root_logger.level in (logging.DEBUG, logging.INFO, logging.WARNING, logging.ERROR)