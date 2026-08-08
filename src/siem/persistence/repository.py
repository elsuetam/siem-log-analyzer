"""Repositório de acesso a dados para incidentes (padrão Repository)."""

from __future__ import annotations

from sqlalchemy import select
from sqlalchemy.orm import Session, sessionmaker

from siem.models.incident import Incident
from siem.persistence.db import session_scope
from siem.persistence.models import IncidentRecord


class IncidentRepository:
    """Encapsula todo o acesso a dados de incidentes, isolando SQL do resto do sistema.

    O resto da aplicação (pipeline, API, CLI) só conhece objetos `Incident`
    (Pydantic) — a conversão para/de registros de banco acontece inteiramente
    dentro desta classe.
    """

    def __init__(self, session_factory: sessionmaker[Session]) -> None:
        self._session_factory = session_factory

    def save_all(self, incidents: list[Incident]) -> None:
        """Persiste uma lista de incidentes no banco.

        Args:
            incidents: incidentes a serem salvos. Incidentes com o mesmo
                incident_id de um já existente são ignorados (não há
                atualização automática nesta versão).
        """
        if not incidents:
            return

        with session_scope(self._session_factory) as session:
            for incident in incidents:
                existing = session.get(IncidentRecord, incident.incident_id)
                if existing is not None:
                    continue
                session.add(self._to_record(incident))

    def list_all(self, limit: int = 100) -> list[Incident]:
        """Retorna os incidentes mais recentes, ordenados do mais novo para o mais antigo.

        Args:
            limit: número máximo de incidentes a retornar.
        """
        with session_scope(self._session_factory) as session:
            stmt = (
                select(IncidentRecord)
                .order_by(IncidentRecord.created_at.desc())
                .limit(limit)
            )
            records = session.execute(stmt).scalars().all()
            return [self._to_incident(record) for record in records]

    def get_by_id(self, incident_id: str) -> Incident | None:
        """Busca um incidente pelo ID. Retorna None se não encontrado."""
        with session_scope(self._session_factory) as session:
            record = session.get(IncidentRecord, incident_id)
            return self._to_incident(record) if record is not None else None

    def list_by_source_ip(self, source_ip: str, limit: int = 100) -> list[Incident]:
        """Retorna incidentes associados a um IP de origem específico."""
        with session_scope(self._session_factory) as session:
            stmt = (
                select(IncidentRecord)
                .where(IncidentRecord.source_ip == source_ip)
                .order_by(IncidentRecord.created_at.desc())
                .limit(limit)
            )
            records = session.execute(stmt).scalars().all()
            return [self._to_incident(record) for record in records]

    def _to_record(self, incident: Incident) -> IncidentRecord:
        return IncidentRecord(
            incident_id=incident.incident_id,
            created_at=incident.created_at,
            status=incident.status.value,
            source_ip=incident.source_ip,
            risk_score=incident.risk_score,
            title=incident.title,
            incident_json=incident.model_dump_json(),
        )

    def _to_incident(self, record: IncidentRecord) -> Incident:
        return Incident.model_validate_json(record.incident_json)