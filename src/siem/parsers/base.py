"""Interface base para todos os parsers de log."""

from __future__ import annotations

from abc import ABC, abstractmethod

from siem.models.log_entry import LogEntry


class BaseParser(ABC):
    """Contrato que todo parser de log deve implementar.

    Cada formato de log (Apache, Nginx, Syslog, JSON, etc.) deve ter sua própria
    implementação concreta desta classe, permitindo adicionar novos formatos sem
    alterar o restante do pipeline.
    """

    @abstractmethod
    def parse_line(self, line: str) -> LogEntry | None:
        """Interpreta uma única linha de log.

        Args:
            line: linha bruta do arquivo de log.

        Returns:
            Uma instância de LogEntry se a linha for válida, ou None se a linha
            deve ser ignorada (ex: linha em branco ou malformada).
        """
        raise NotImplementedError