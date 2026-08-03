"""Modelo de dados que representa um evento suspeito identificado por um detector."""

from __future__ import annotations

from datetime import datetime
from enum import StrEnum

from pydantic import BaseModel, Field


class DetectionSeverity(StrEnum):
    """Nível de severidade de um evento de detecção."""

    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class DetectionEvent(BaseModel):
    """Representa uma ocorrência suspeita identificada por um detector.

    Este é o "contrato de saída" de todo detector. Etapas futuras (score de
    risco, correlação, incidentes) consomem apenas DetectionEvent — nunca
    LogEntry diretamente — mantendo o pipeline desacoplado.
    """

    detector_name: str = Field(description="Nome do detector que gerou o evento.")
    severity: DetectionSeverity = Field(description="Severidade da detecção.")
    source_ip: str = Field(description="IP de origem associado ao evento.")
    description: str = Field(description="Descrição legível do que foi detectado.")
    first_seen: datetime = Field(
        description="Timestamp da primeira ocorrência na janela detectada."
    )
    last_seen: datetime = Field(
        description="Timestamp da última ocorrência na janela detectada."
    )
    occurrence_count: int = Field(
        ge=1, description="Número de ocorrências que geraram esta detecção."
    )