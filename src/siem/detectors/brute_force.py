"""Detector de tentativas de brute force (múltiplas falhas de autenticação)."""

from __future__ import annotations

from collections import defaultdict
from datetime import timedelta

from siem.detectors.base import BaseDetector
from siem.models.detection_event import DetectionEvent, DetectionSeverity
from siem.models.log_entry import LogEntry

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
            events.extend(self._detect_windows(source_ip, failures))

        return events

    def _is_auth_failure(self, entry: LogEntry) -> bool:
        if entry.status_code not in _AUTH_FAILURE_STATUS_CODES:
            return False
        path_lower = entry.path.lower()
        return any(hint in path_lower for hint in _LOGIN_PATH_HINTS)

    def _detect_windows(self, source_ip: str, failures: list[LogEntry]) -> list[DetectionEvent]:
        """Aplica uma janela deslizante sobre as falhas ordenadas de um IP.

        Usa uma estratégia de ponteiro duplo (sliding window) para agrupar
        falhas que ocorrem dentro do intervalo de tempo configurado.
        """
        events: list[DetectionEvent] = []
        window_start_idx = 0

        for end_idx in range(len(failures)):
            while failures[end_idx].timestamp - failures[window_start_idx].timestamp > self._window:
                window_start_idx += 1

            window_size = end_idx - window_start_idx + 1
            if window_size >= self._attempts_threshold:
                window_entries = failures[window_start_idx : end_idx + 1]
                events.append(self._build_event(source_ip, window_entries))
                # Avança o início da janela para evitar sobreposição de detecções
                window_start_idx = end_idx + 1

        return events

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
        )