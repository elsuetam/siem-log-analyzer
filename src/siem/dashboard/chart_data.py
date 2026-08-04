"""Agregação de dados para os gráficos exibidos no dashboard."""

from __future__ import annotations

from collections import Counter
from dataclasses import dataclass

from siem.models.incident import Incident


@dataclass
class SeverityCount:
    """Contagem de incidentes para um nível de severidade específico."""

    severity: str
    count: int
    percentage: float


@dataclass
class TopSourceIP:
    """Um IP de origem no ranking dos mais arriscados."""

    source_ip: str
    score: float
    percentage: float


_SEVERITY_ORDER = ["critical", "high", "medium", "low"]


def build_severity_distribution(incidents: list[Incident]) -> list[SeverityCount]:
    """Calcula a distribuição de incidentes por severidade máxima de cada um.

    Args:
        incidents: lista de incidentes gerados pelo pipeline.

    Returns:
        Lista de SeverityCount na ordem critical -> high -> medium -> low,
        omitindo severidades sem nenhuma ocorrência. As porcentagens são
        relativas ao maior valor do grupo (para dimensionar barras no template).
    """
    if not incidents:
        return []

    counts = Counter(_highest_severity(incident) for incident in incidents)
    max_count = max(counts.values())

    return [
        SeverityCount(
            severity=severity,
            count=counts[severity],
            percentage=(counts[severity] / max_count) * 100,
        )
        for severity in _SEVERITY_ORDER
        if counts[severity] > 0
    ]


def build_top_source_ips(incidents: list[Incident], limit: int = 5) -> list[TopSourceIP]:
    """Calcula o ranking dos IPs com maior score de risco.

    Args:
        incidents: lista de incidentes gerados pelo pipeline.
        limit: número máximo de IPs a incluir no ranking.

    Returns:
        Lista de TopSourceIP ordenada do maior para o menor score, limitada a
        `limit` itens. As porcentagens são relativas ao maior score do grupo.
    """
    if not incidents:
        return []

    sorted_incidents = sorted(incidents, key=lambda i: i.risk_score, reverse=True)[:limit]
    max_score = sorted_incidents[0].risk_score or 1.0

    return [
        TopSourceIP(
            source_ip=incident.source_ip,
            score=incident.risk_score,
            percentage=(incident.risk_score / max_score) * 100,
        )
        for incident in sorted_incidents
    ]


def _highest_severity(incident: Incident) -> str:
    severities = [event.severity.value for event in incident.risk_details.contributing_events]
    for level in _SEVERITY_ORDER:
        if level in severities:
            return level
    return "low"