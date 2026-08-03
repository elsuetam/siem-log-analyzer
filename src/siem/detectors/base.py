"""Interface base para todos os detectores de eventos suspeitos."""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Any

from siem.models.log_entry import LogEntry


class BaseDetector(ABC):
    """Contrato que todo detector de ameaças deve implementar.

    Cada tipo de detecção (brute force, SQL Injection, scanners, etc.) é uma
    implementação concreta desta classe, permitindo adicionar novas regras
    (incluindo futuramente Sigma Rules / YARA) sem alterar o pipeline principal.
    """

    @abstractmethod
    def detect(self, entries: list[LogEntry]) -> list[dict[str, Any]]:
        """Analisa uma lista de entradas de log e retorna eventos suspeitos encontrados.

        Args:
            entries: lista de LogEntry já parseadas.

        Returns:
            Lista de dicionários descrevendo cada ocorrência suspeita encontrada.
            O formato exato será definido/tipado na etapa de "Detectores de eventos".
        """
        raise NotImplementedError