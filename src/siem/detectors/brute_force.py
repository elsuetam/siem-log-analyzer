"""Detector de tentativas de brute force (múltiplas falhas de autenticação)."""

from __future__ import annotations

from collections import defaultdict
from datetime import timedelta

from siem.detectors.base import BaseDetector
from siem.mitre.attack_reference import BRUTE_FORCE
from siem.models.detection_event import DetectionEvent, DetectionSeverity
from siem.models.log_entry import LogEntry
from siem.utils.sliding_window import find_windows_meeting_threshold

# Status codes que indicam falha de autenticação/autorização
_AUTH_FAILURE_STATUS_CODES = {401, 403}

# Paths comumente associados a login; usado para reduzir falsos positivos
# quando combinado com status de falha. Mantido simples nesta etapa —
# pode evoluir para configuração externa futuramente.
_LOGIN_PATH_HINTS = ("login", "signin", "auth", "sso")


class BruteForceDetector(BaseDetector):
    """Detecta possíveis ataques de brute force por IP de origem.

    Um IP é sinalizado quando acumula um número de respostas de falha de
    autenticação (401/403) em endpoints de login igual ou superior ao
    threshold configurado, dentro da janela de tempo configurada.
    """

    def __init__(self, attempts_threshold: int, window_seconds: int) -> None:
        """Inicializa o detector com os parâmetros de sensibilidade.

        Args:
            attempts_threshold: número mínimo de falhas para gerar uma detecção.
            window_seconds: janela de tempo (segundos) considerada para agrupar falhas.
        """
        self._attempts_threshold = attempts_threshold
        self._window = timedelta(seconds=window_seconds)

    @property
    def name(self) -> str:
        return "brute_force_detector"

    def detect(self, entries: list[LogEntry]) -> list[DetectionEvent]:
        failures_by_ip: dict[str, list[LogEntry]] = defaultdict(list)

        for entry in entries:
            if self._is_auth_failure(entry):
                failures_by_ip[entry.source_ip].append(entry)

        events: list[DetectionEvent] = []
        for source_ip, failures in failures_by_ip.items():
            failures.sort(key=lambda e: e.timestamp)
            windows = find_windows_meeting_threshold(
                items=failures,
                get_timestamp=lambda e: e.timestamp,
                window=self._window,
                meets_threshold=lambda group: len(group) >= self._attempts_threshold,
            )
            events.extend(self._build_event(source_ip, group) for group in windows)

        return events

    def _is_auth_failure(self, entry: LogEntry) -> bool:
        if entry.status_code not in _AUTH_FAILURE_STATUS_CODES:
            return False
        path_lower = entry.path.lower()
        return any(hint in path_lower for hint in _LOGIN_PATH_HINTS)

    def _build_event(self, source_ip: str, window_entries: list[LogEntry]) -> DetectionEvent:
        return DetectionEvent(
            detector_name=self.name,
            severity=DetectionSeverity.HIGH,
            source_ip=source_ip,
            description=(
                f"{len(window_entries)} tentativas de autenticação falhas detectadas "
                f"para o IP {source_ip} em uma janela de {self._window.total_seconds():.0f}s."
            ),
            first_seen=window_entries[0].timestamp,
            last_seen=window_entries[-1].timestamp,
            occurrence_count=len(window_entries),
            mitre_technique_id=BRUTE_FORCE.technique_id,
            mitre_technique_name=BRUTE_FORCE.name,
        )