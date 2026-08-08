"""Modelos de resposta da API REST."""

from __future__ import annotations

from pydantic import BaseModel, Field

from siem.models.incident import Incident


class HealthResponse(BaseModel):
    """Resposta do endpoint de healthcheck."""

    status: str = Field(default="ok")


class AnalyzeResponse(BaseModel):
    """Resposta da execução de uma análise via /analyze."""

    total_entries: int
    total_detections: int
    incidents: list[Incident]


class IncidentsResponse(BaseModel):
    """Resposta da consulta aos incidentes da última análise."""

    incidents: list[Incident]
    analyzed_at: str | None = Field(
        default=None, description="Timestamp da última análise executada, se houver."
    )