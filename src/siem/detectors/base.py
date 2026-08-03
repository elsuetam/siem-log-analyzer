"""Interface base para todos os detectores de eventos suspeitos."""

from __future__ import annotations

from abc import ABC, abstractmethod

from siem.models.detection_event import DetectionEvent
from siem.models.log_entry import LogEntry


class BaseDetector(ABC):
    """Contrato que todo detector de ameaças deve implementar.

    Cada tipo de detecção (brute force, SQL Injection, scanners, etc.) é uma
    implementação concreta desta classe, permitindo adicionar novas regras
    (incluindo futuramente Sigma Rules / YARA) sem alterar o pipeline principal.
    """

    @property
    @abstractmethod
    def name(self) -> str:
        """Identificador legível do detector (usado em DetectionEvent.detector_name)."""
        raise NotImplementedError

    @abstractmethod
    def detect(self, entries: list[LogEntry]) -> list[DetectionEvent]:
        """Analisa uma lista de entradas de log e retorna eventos suspeitos encontrados.

        Args:
            entries: lista de LogEntry já parseadas, tipicamente ordenadas por
                timestamp (mas implementações não devem assumir ordenação).

        Returns:
            Lista de DetectionEvent, uma para cada ocorrência suspeita agrupada
            (ex: um DetectionEvent por IP que excedeu o threshold, não um por linha de log).
        """
        raise NotImplementedError