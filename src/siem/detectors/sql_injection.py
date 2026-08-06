"""Detector de tentativas de SQL Injection via padrões no path/query string."""

from __future__ import annotations

import re
from collections import defaultdict

from siem.detectors.base import BaseDetector
from siem.models.detection_event import DetectionEvent, DetectionSeverity
from siem.models.log_entry import LogEntry

# Padrões comuns de SQL Injection. Não é uma lista exaustiva — cobre os
# vetores mais frequentes (tautologias, UNION-based, comentários SQL,
# injeção de comandos de escrita). Mantido em regex simples e legível;
# para cobertura mais ampla no futuro, considerar migrar para Sigma Rules.
_SQLI_PATTERNS = [
    re.compile(r"(\%27)|(')|(--)|(\%23)|(#)", re.IGNORECASE),  # aspas, comentários SQL
    re.compile(r"(\bOR\b|\bAND\b)\s+['\"]?\d+['\"]?\s*=\s*['\"]?\d+", re.IGNORECASE),  # OR 1=1
    re.compile(r"\bUNION\b.{0,40}\bSELECT\b", re.IGNORECASE),
    re.compile(r"\b(DROP|DELETE|INSERT|UPDATE)\b.{0,40}\b(TABLE|FROM|INTO)\b", re.IGNORECASE),
    re.compile(r";\s*(DROP|SHUTDOWN|EXEC)\b", re.IGNORECASE),
]


class SqlInjectionDetector(BaseDetector):
    """Detecta tentativas de SQL Injection através de padrões no path da requisição.

    Diferente de BruteForceDetector e ScannerDetector, este detector não usa
    janela de tempo — uma única requisição contendo um padrão suspeito já é
    significativa, independente de frequência.
    """

    @property
    def name(self) -> str:
        return "sql_injection_detector"

    def detect(self, entries: list[LogEntry]) -> list[DetectionEvent]:
        matches_by_ip: dict[str, list[LogEntry]] = defaultdict(list)

        for entry in entries:
            if self._matches_sqli_pattern(entry.path):
                matches_by_ip[entry.source_ip].append(entry)

        return [self._build_event(ip, matches) for ip, matches in matches_by_ip.items()]

    def _matches_sqli_pattern(self, path: str) -> bool:
        return any(pattern.search(path) for pattern in _SQLI_PATTERNS)

    def _build_event(self, source_ip: str, matches: list[LogEntry]) -> DetectionEvent:
        sorted_matches = sorted(matches, key=lambda e: e.timestamp)
        return DetectionEvent(
            detector_name=self.name,
            severity=DetectionSeverity.CRITICAL,
            source_ip=source_ip,
            description=(
                f"{len(matches)} requisição(ões) com padrão de SQL Injection "
                f"detectada(s) do IP {source_ip}."
            ),
            first_seen=sorted_matches[0].timestamp,
            last_seen=sorted_matches[-1].timestamp,
            occurrence_count=len(matches),
        )