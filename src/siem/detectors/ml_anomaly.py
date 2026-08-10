"""Detector de anomalias comportamentais via Machine Learning (Isolation Forest).

Diferente dos demais detectores (baseados em regras explícitas), este
identifica IPs cujo padrão de comportamento se desvia estatisticamente do
restante do tráfego observado na mesma execução — sem que nenhuma regra
tenha sido escrita manualmente para esse padrão específico.

Requer um volume mínimo de IPs distintos para fazer sentido estatístico
(configurável); com poucos dados, o detector simplesmente não gera
detecções, em vez de arriscar falsos positivos por falta de amostra.
"""

from __future__ import annotations

import logging
from collections import defaultdict
from dataclasses import dataclass

from siem.detectors.base import BaseDetector
from siem.models.detection_event import DetectionEvent, DetectionSeverity
from siem.models.log_entry import LogEntry

logger = logging.getLogger(__name__)

try:
    import numpy as np
    from sklearn.ensemble import IsolationForest

    _SKLEARN_AVAILABLE = True
except ImportError:  # pragma: no cover - depende de dependência opcional
    _SKLEARN_AVAILABLE = False


@dataclass
class _IPFeatures:
    """Vetor de features comportamentais agregadas por IP de origem."""

    source_ip: str
    request_count: int
    distinct_paths: int
    distinct_methods: int
    error_rate: float  # proporção de respostas com status >= 400
    avg_bytes_sent: float

    def as_vector(self) -> list[float]:
        """Converte as features em um vetor numérico para o modelo."""
        return [
            float(self.request_count),
            float(self.distinct_paths),
            float(self.distinct_methods),
            self.error_rate,
            self.avg_bytes_sent,
        ]


class MLAnomalyDetector(BaseDetector):
    """Detecta IPs com comportamento estatisticamente anômalo via Isolation Forest.

    Se scikit-learn/numpy não estiverem instalados, ou o número de IPs
    distintos for menor que `min_ips_required`, o detector não gera
    detecções — nunca interrompe o restante do pipeline.
    """

    def __init__(
        self,
        contamination: float = 0.1,
        min_ips_required: int = 10,
        random_state: int = 42,
    ) -> None:
        """Inicializa o detector.

        Args:
            contamination: proporção esperada de IPs anômalos no conjunto
                (hiperparâmetro do Isolation Forest; 0.1 = ~10% mais estranhos).
            min_ips_required: número mínimo de IPs distintos para rodar o
                modelo — abaixo disso, não há amostra suficiente para uma
                análise estatística confiável.
            random_state: seed para reprodutibilidade dos resultados.
        """
        self._contamination = contamination
        self._min_ips_required = min_ips_required
        self._random_state = random_state

    @property
    def name(self) -> str:
        return "ml_anomaly_detector"

    def detect(self, entries: list[LogEntry]) -> list[DetectionEvent]:
        if not _SKLEARN_AVAILABLE:
            logger.info("scikit-learn não disponível; detector de anomalias desativado.")
            return []

        features_by_ip = self._extract_features(entries)
        if len(features_by_ip) < self._min_ips_required:
            logger.info(
                "Apenas %d IP(s) distintos (mínimo %d); pulando detecção de anomalias.",
                len(features_by_ip),
                self._min_ips_required,
            )
            return []

        anomalous_ips = self._find_anomalies(features_by_ip)

        events: list[DetectionEvent] = []
        entries_by_ip: dict[str, list[LogEntry]] = defaultdict(list)
        for entry in entries:
            entries_by_ip[entry.source_ip].append(entry)

        for source_ip in anomalous_ips:
            events.append(self._build_event(source_ip, entries_by_ip[source_ip]))

        return events

    def _extract_features(self, entries: list[LogEntry]) -> dict[str, _IPFeatures]:
        entries_by_ip: dict[str, list[LogEntry]] = defaultdict(list)
        for entry in entries:
            entries_by_ip[entry.source_ip].append(entry)

        features: dict[str, _IPFeatures] = {}
        for source_ip, ip_entries in entries_by_ip.items():
            error_count = sum(1 for e in ip_entries if e.status_code >= 400)
            features[source_ip] = _IPFeatures(
                source_ip=source_ip,
                request_count=len(ip_entries),
                distinct_paths=len({e.path for e in ip_entries}),
                distinct_methods=len({e.method for e in ip_entries}),
                error_rate=error_count / len(ip_entries),
                avg_bytes_sent=sum(e.bytes_sent for e in ip_entries) / len(ip_entries),
            )
        return features

    def _find_anomalies(self, features_by_ip: dict[str, _IPFeatures]) -> list[str]:
        ips = list(features_by_ip.keys())
        vectors = np.array([features_by_ip[ip].as_vector() for ip in ips])

        model = IsolationForest(
            contamination=self._contamination,
            random_state=self._random_state,
        )
        predictions = model.fit_predict(vectors)  # -1 = anomalia, 1 = normal

        return [ip for ip, prediction in zip(ips, predictions, strict=True) if prediction == -1]

    def _build_event(self, source_ip: str, matches: list[LogEntry]) -> DetectionEvent:
        sorted_matches = sorted(matches, key=lambda e: e.timestamp)
        return DetectionEvent(
            detector_name=self.name,
            severity=DetectionSeverity.MEDIUM,
            source_ip=source_ip,
            description=(
                f"Comportamento estatisticamente anômalo detectado para o IP {source_ip} "
                "(Isolation Forest, sem regra explícita associada)."
            ),
            first_seen=sorted_matches[0].timestamp,
            last_seen=sorted_matches[-1].timestamp,
            occurrence_count=len(matches),
        )