"""Modelo ORM (SQLAlchemy) para persistência de incidentes."""

from __future__ import annotations

from datetime import datetime

from sqlalchemy import DateTime, Float, String
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column


class Base(DeclarativeBase):
    """Classe base declarativa para os modelos ORM do projeto."""


class IncidentRecord(Base):
    """Representação em banco de dados de um Incident.

    Campos ricos (risk_details, geo_location) são armazenados como JSON
    serializado — não precisamos de tabelas relacionais normalizadas para
    esse volume de dados, e isso evita joins desnecessários para um caso
    de uso que é majoritariamente "salvar e listar".
    """

    __tablename__ = "incidents"

    incident_id: Mapped[str] = mapped_column(String(36), primary_key=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    status: Mapped[str] = mapped_column(String(20))
    source_ip: Mapped[str] = mapped_column(String(45), index=True)
    risk_score: Mapped[float] = mapped_column(Float, index=True)
    title: Mapped[str] = mapped_column(String(500))
    incident_json: Mapped[str] = mapped_column(
        String, doc="Serialização JSON completa do Incident (Pydantic .model_dump_json())."
    )