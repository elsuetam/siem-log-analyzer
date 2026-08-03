"""Cálculo de score de risco a partir dos resultados dos detectores.

Implementação real será desenvolvida na etapa correspondente ("Sistema de Score
de Risco"). Este arquivo existe desde já para fixar o ponto de extensão na
arquitetura.
"""

from __future__ import annotations


def calculate_risk_score(detections: list[dict]) -> float:
    """Calcula um score de risco agregado a partir das detecções encontradas.

    Args:
        detections: lista de eventos suspeitos retornados pelos detectores.

    Returns:
        Score de risco (0.0 a 100.0). Implementação real pendente.
    """
    raise NotImplementedError("Será implementado na etapa de Score de Risco.")