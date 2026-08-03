"""Modelo de dados que representa uma entrada de log normalizada.

Este modelo será expandido na etapa de "Modelos de dados" com campos adicionais
(ex: user_agent, status_code, método HTTP, path). Por ora, mantém apenas o
essencial para viabilizar a interface de parsers/detectores.
"""

from __future__ import annotations

from datetime import datetime

from pydantic import BaseModel, Field


class LogEntry(BaseModel):
    """Representa uma única linha de log já normalizada."""

    timestamp: datetime
    source_ip: str = Field(description="Endereço IP de origem da requisição/evento")
    raw_line: str = Field(description="Linha original do log, preservada para auditoria")