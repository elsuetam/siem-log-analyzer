"""Interface base para todos os parsers de log."""

from __future__ import annotations

from abc import ABC, abstractmethod

from siem.models.log_entry import LogEntry


class BaseParser(ABC):
    """Contrato que todo parser de log deve implementar.

    Cada formato de log (Apache/Nginx Combined, Syslog, JSON, etc.) deve ter
    sua própria implementação concreta desta classe, permitindo adicionar
    novos formatos sem alterar o restante do pipeline.
    """

    @abstractmethod
    def parse_line(self, line: str) -> LogEntry | None:
        """Interpreta uma única linha de log.

        Args:
            line: linha bruta do arquivo de log.

        Returns:
            Uma instância de LogEntry se a linha for válida, ou None se a linha
            deve ser silenciosamente ignorada (ex: linha em branco).

        Raises:
            MalformedLogLineError: se a linha não estiver vazia mas não puder
                ser interpretada no formato esperado pelo parser.
        """
        raise NotImplementedError

    def parse_lines(self, lines: list[str]) -> list[LogEntry]:
        """Interpreta múltiplas linhas, ignorando as que retornam None.

        Implementação padrão baseada em `parse_line`; parsers concretos
        normalmente não precisam sobrescrever este método.
        """
        entries: list[LogEntry] = []
        for line in lines:
            entry = self.parse_line(line)
            if entry is not None:
                entries.append(entry)
        return entries