"""Detector de comportamento de scanning (varredura de múltiplos paths)."""

from __future__ import annotations

from collections import defaultdict
from datetime import timedelta

from siem.detectors.base import BaseDetector
from siem.models.detection_event import DetectionEvent, DetectionSeverity
from siem.models.log_entry import LogEntry


class ScannerDetector(BaseDetector):
    """Detecta possível comportamento de scanning/reconhecimento por IP.

    Um IP é sinalizado quando acessa um número de paths *distintos* igual ou
    superior ao threshold configurado, dentro da janela de tempo configurada —
    padrão típico de ferramentas de fuzzing/enumeração (ex: dirbuster, nikto).
    """

    def __init__(self, requests_threshold: int, window_seconds: int) -> None:
        """Inicializa o detector com os parâmetros de sensibilidade.

        Args:
            requests_threshold: número mínimo de paths distintos para gerar detecção.
            window_seconds: janela de tempo (segundos) considerada.
        """
        self._requests_threshold = requests_threshold
        self._window = timedelta(seconds=window_seconds)

    @property
    def name(self) -> str:
        return "scanner_detector"

    def detect(self, entries: list[LogEntry]) -> list[DetectionEvent]:
        entries_by_ip: dict[str, list[LogEntry]] = defaultdict(list)
        for entry in entries:
            entries_by_ip[entry.source_ip].append(entry)

        events: list[DetectionEvent] = []
        for source_ip, ip_entries in entries_by_ip.items():
            ip_entries.sort(key=lambda e: e.timestamp)
            events.extend(self._detect_windows(source_ip, ip_entries))

        return events

    def _detect_windows(self, source_ip: str, ip_entries: list[LogEntry]) -> list[DetectionEvent]:
        events: list[DetectionEvent] = []
        window_start_idx = 0

        for end_idx in range(len(ip_entries)):
            while (
                ip_entries[end_idx].timestamp - ip_entries[window_start_idx].timestamp
                > self._window
            ):
                window_start_idx += 1

            window_entries = ip_entries[window_start_idx : end_idx + 1]
            distinct_paths = {e.path for e in window_entries}

            if len(distinct_paths) >= self._requests_threshold:
                events.append(self._build_event(source_ip, window_entries, distinct_paths))
                window_start_idx = end_idx + 1

        return events

    def _build_event(
        self,
        source_ip: str,
        window_entries: list[LogEntry],
        distinct_paths: set[str],
    ) -> DetectionEvent:
        return DetectionEvent(
            detector_name=self.name,
            severity=DetectionSeverity.MEDIUM,
            source_ip=source_ip,
            description=(
                f"{len(distinct_paths)} paths distintos acessados pelo IP {source_ip} "
                f"em uma janela de {self._window.total_seconds():.0f}s "
                "(possível varredura/reconhecimento)."
            ),
            first_seen=window_entries[0].timestamp,
            last_seen=window_entries[-1].timestamp,
            occurrence_count=len(window_entries),
        )