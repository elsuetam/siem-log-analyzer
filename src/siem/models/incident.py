"""Modelo de dados que representa um incidente de segurança formal."""

from __future__ import annotations

import uuid
from datetime import UTC, datetime
from enum import StrEnum

from pydantic import BaseModel, Field

from siem.models.risk_score import RiskScore


class IncidentStatus(StrEnum):
    """Status de acompanhamento de um incidente."""

    OPEN = "open"
    ACKNOWLEDGED = "acknowledged"
    CLOSED = "closed"


class Incident(BaseModel):
    """Representa um incidente de segurança formal, gerado a partir de um
    RiskScore que ultrapassou o threshold de criação de incidentes.

    Este é o registro que será exibido no dashboard e nos relatórios —
    a "unidade de trabalho" que um analista de segurança vai revisar.
    """

    incident_id: str = Field(
        default_factory=lambda: str(uuid.uuid4()),
        description="Identificador único do incidente.",
    )
    created_at: datetime = Field(
        default_factory=lambda: datetime.now(UTC),
        description="Momento em que o incidente foi gerado pelo sistema.",
    )
    status: IncidentStatus = Field(
        default=IncidentStatus.OPEN,
        description="Status atual de acompanhamento do incidente.",
    )
    source_ip: str = Field(description="IP de origem associado ao incidente.")
    risk_score: float = Field(
        ge=0.0, le=100.0, description="Score de risco que originou este incidente."
    )
    title: str = Field(description="Título curto e legível do incidente.")
    risk_details: RiskScore = Field(
        description="Detalhamento completo do score de risco (eventos contribuintes)."
    )