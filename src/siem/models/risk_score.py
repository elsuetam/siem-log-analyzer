"""Modelo de dados que representa o score de risco agregado de um IP."""

from __future__ import annotations

from pydantic import BaseModel, Field

from siem.models.detection_event import DetectionEvent


class RiskScore(BaseModel):
    """Score de risco agregado para um IP de origem, calculado a partir de
    todos os DetectionEvent associados a ele.
    """

    source_ip: str = Field(description="IP de origem ao qual este score se refere.")
    score: float = Field(ge=0.0, le=100.0, description="Score de risco agregado (0 a 100).")
    contributing_events: list[DetectionEvent] = Field(
        description="Eventos de detecção que contribuíram para este score."
    )
    distinct_detectors: int = Field(
        ge=0, description="Número de detectores distintos que sinalizaram este IP."
    )