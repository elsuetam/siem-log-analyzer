"""Cálculo de score de risco a partir dos resultados dos detectores."""

from __future__ import annotations

from collections import defaultdict

from siem.models.detection_event import DetectionEvent, DetectionSeverity
from siem.models.risk_score import RiskScore

# Peso-base por severidade individual de um evento de detecção.
_SEVERITY_WEIGHTS: dict[DetectionSeverity, float] = {
    DetectionSeverity.LOW: 5.0,
    DetectionSeverity.MEDIUM: 15.0,
    DetectionSeverity.HIGH: 30.0,
    DetectionSeverity.CRITICAL: 50.0,
}

# Bônus adicional por cada detector distinto acionado além do primeiro —
# um IP sinalizado por múltiplos detectores diferentes é mais preocupante
# do que o mesmo detector disparando várias vezes.
_MULTI_DETECTOR_BONUS = 10.0

_MAX_SCORE = 100.0


def calculate_risk_scores(detections: list[DetectionEvent]) -> list[RiskScore]:
    """Calcula o score de risco agregado para cada IP presente nas detecções.

    Args:
        detections: lista de eventos de detecção de todos os detectores executados.

    Returns:
        Lista de RiskScore, um por IP distinto encontrado em `detections`,
        ordenada do maior para o menor score.
    """
    events_by_ip: dict[str, list[DetectionEvent]] = defaultdict(list)
    for event in detections:
        events_by_ip[event.source_ip].append(event)

    scores = [
        _calculate_score_for_ip(source_ip, events) for source_ip, events in events_by_ip.items()
    ]
    scores.sort(key=lambda s: s.score, reverse=True)
    return scores


def _calculate_score_for_ip(source_ip: str, events: list[DetectionEvent]) -> RiskScore:
    base_score = sum(_SEVERITY_WEIGHTS[event.severity] for event in events)

    distinct_detectors = len({event.detector_name for event in events})
    diversity_bonus = max(0, distinct_detectors - 1) * _MULTI_DETECTOR_BONUS

    total_score = min(base_score + diversity_bonus, _MAX_SCORE)

    return RiskScore(
        source_ip=source_ip,
        score=total_score,
        contributing_events=events,
        distinct_detectors=distinct_detectors,
    )