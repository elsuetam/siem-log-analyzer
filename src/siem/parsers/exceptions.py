"""Exceções customizadas para o módulo de parsers."""

from __future__ import annotations


class LogParsingError(Exception):
    """Exceção base para erros de parsing de log."""


class MalformedLogLineError(LogParsingError):
    """Levantada quando uma linha de log não corresponde ao formato esperado."""

    def __init__(self, line: str, reason: str) -> None:
        self.line = line
        self.reason = reason
        super().__init__(f"Linha malformada ({reason}): {line!r}")