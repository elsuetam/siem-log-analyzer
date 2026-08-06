"""Detector de tentativas de Directory Traversal via padrões no path."""

from __future__ import annotations

import re
from collections import defaultdict

from siem.detectors.base import BaseDetector
from siem.mitre.attack_reference import EXPLOIT_PUBLIC_FACING_APPLICATION
from siem.models.detection_event import DetectionEvent, DetectionSeverity
from siem.models.log_entry import LogEntry

# Padrões de directory traversal, incluindo variantes com URL-encoding
# (simples e duplo) comumente usadas para evadir filtros ingênuos.
_TRAVERSAL_PATTERNS = [
    re.compile(r"\.\./"),  # ../
    re.compile(r"\.\.\\"),  # ..\
    re.compile(r"%2e%2e%2f", re.IGNORECASE),  # ../ codificado
    re.compile(r"%2e%2e/", re.IGNORECASE),  # variante parcialmente codificada
    re.compile(r"\.\.%2f", re.IGNORECASE),  # variante parcialmente codificada
    re.compile(r"(etc/passwd|boot\.ini|win\.ini)", re.IGNORECASE),  # alvos clássicos
]


class DirectoryTraversalDetector(BaseDetector):
    """Detecta tentativas de acessar arquivos fora do diretório esperado.

    Assim como SqlInjectionDetector, não depende de janela de tempo — um
    único path com padrão de traversal já é uma detecção relevante.
    """

    @property
    def name(self) -> str:
        return "directory_traversal_detector"

    def detect(self, entries: list[LogEntry]) -> list[DetectionEvent]:
        matches_by_ip: dict[str, list[LogEntry]] = defaultdict(list)

        for entry in entries:
            if self._matches_traversal_pattern(entry.path):
                matches_by_ip[entry.source_ip].append(entry)

        return [self._build_event(ip, matches) for ip, matches in matches_by_ip.items()]

    def _matches_traversal_pattern(self, path: str) -> bool:
        return any(pattern.search(path) for pattern in _TRAVERSAL_PATTERNS)

    def _build_event(self, source_ip: str, matches: list[LogEntry]) -> DetectionEvent:
        sorted_matches = sorted(matches, key=lambda e: e.timestamp)
        return DetectionEvent(
            detector_name=self.name,
            severity=DetectionSeverity.HIGH,
            source_ip=source_ip,
            description=(
                f"{len(matches)} requisição(ões) com padrão de Directory Traversal "
                f"detectada(s) do IP {source_ip}."
            ),
            first_seen=sorted_matches[0].timestamp,
            last_seen=sorted_matches[-1].timestamp,
            occurrence_count=len(matches),
            mitre_technique_id=EXPLOIT_PUBLIC_FACING_APPLICATION.technique_id,
            mitre_technique_name=EXPLOIT_PUBLIC_FACING_APPLICATION.name,
        )