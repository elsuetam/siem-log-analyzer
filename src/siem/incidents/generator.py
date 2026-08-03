"""Geração de incidentes formais a partir de scores de risco."""

from __future__ import annotations

from siem.models.incident import Incident
from siem.models.risk_score import RiskScore


def generate_incidents(risk_scores: list[RiskScore], threshold: float) -> list[Incident]:
    """Gera incidentes formais para os IPs cujo score de risco atinge o threshold.

    Args:
        risk_scores: lista de scores de risco calculados (tipicamente já
            ordenada do maior para o menor, mas a ordenação não é assumida aqui).
        threshold: score mínimo (0-100) para que um RiskScore gere um Incident.

    Returns:
        Lista de Incident, um por RiskScore que atingiu o threshold,
        ordenada do maior score para o menor.
    """
    qualifying_scores = [rs for rs in risk_scores if rs.score >= threshold]
    qualifying_scores.sort(key=lambda rs: rs.score, reverse=True)

    return [_build_incident(risk_score) for risk_score in qualifying_scores]


def _build_incident(risk_score: RiskScore) -> Incident:
    detector_names = sorted({event.detector_name for event in risk_score.contributing_events})
    title = (
        f"Atividade suspeita detectada de {risk_score.source_ip} "
        f"(score {risk_score.score:.0f}, detectores: {', '.join(detector_names)})"
    )

    return Incident(
        source_ip=risk_score.source_ip,
        risk_score=risk_score.score,
        title=title,
        risk_details=risk_score,
    )