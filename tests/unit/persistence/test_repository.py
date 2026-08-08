"""Testes unitários para IncidentRepository."""

from __future__ import annotations

from datetime import UTC, datetime

import pytest
from sqlalchemy.orm import Session, sessionmaker

from siem.models.detection_event import DetectionEvent, DetectionSeverity
from siem.models.incident import Incident
from siem.models.risk_score import RiskScore
from siem.persistence.db import create_session_factory
from siem.persistence.repository import IncidentRepository

BASE_TIME = datetime(2024, 1, 1, 12, 0, 0, tzinfo=UTC)


def make_incident(source_ip: str, score: float) -> Incident:
    event = DetectionEvent(
        detector_name="brute_force_detector",
        severity=DetectionSeverity.HIGH,
        source_ip=source_ip,
        description="evento de teste",
        first_seen=BASE_TIME,
        last_seen=BASE_TIME,
        occurrence_count=1,
    )
    risk_score = RiskScore(
        source_ip=source_ip, score=score, contributing_events=[event], distinct_detectors=1
    )
    return Incident(
        source_ip=source_ip, risk_score=score, title=f"Teste {source_ip}", risk_details=risk_score
    )


@pytest.fixture
def session_factory() -> sessionmaker[Session]:
    # SQLite em memória: rápido, isolado, descartado ao final de cada teste.
    return create_session_factory("sqlite:///:memory:")


@pytest.fixture
def repository(session_factory: sessionmaker[Session]) -> IncidentRepository:
    return IncidentRepository(session_factory)


def test_save_all_with_empty_list_does_nothing(repository: IncidentRepository) -> None:
    """Salvar uma lista vazia não deve gerar erro nem registros."""
    repository.save_all([])

    assert repository.list_all() == []


def test_save_and_list_all_returns_saved_incident(repository: IncidentRepository) -> None:
    """Um incidente salvo deve aparecer em list_all() com os mesmos dados."""
    incident = make_incident("1.2.3.4", 50.0)

    repository.save_all([incident])
    result = repository.list_all()

    assert len(result) == 1
    assert result[0].incident_id == incident.incident_id
    assert result[0].source_ip == "1.2.3.4"
    assert result[0].risk_score == 50.0


def test_save_all_ignores_duplicate_incident_ids(repository: IncidentRepository) -> None:
    """Salvar o mesmo incident_id duas vezes não deve gerar duplicata nem erro."""
    incident = make_incident("1.2.3.4", 50.0)

    repository.save_all([incident])
    repository.save_all([incident])

    assert len(repository.list_all()) == 1


def test_get_by_id_returns_matching_incident(repository: IncidentRepository) -> None:
    """get_by_id deve retornar o incidente correto pelo ID."""
    incident = make_incident("9.9.9.9", 75.0)
    repository.save_all([incident])

    result = repository.get_by_id(incident.incident_id)

    assert result is not None
    assert result.source_ip == "9.9.9.9"


def test_get_by_id_returns_none_when_not_found(repository: IncidentRepository) -> None:
    """get_by_id deve retornar None para um ID inexistente."""
    result = repository.get_by_id("id-que-nao-existe")

    assert result is None


def test_list_by_source_ip_filters_correctly(repository: IncidentRepository) -> None:
    """list_by_source_ip deve retornar apenas incidentes do IP solicitado."""
    repository.save_all([make_incident("1.1.1.1", 30.0), make_incident("2.2.2.2", 60.0)])

    result = repository.list_by_source_ip("1.1.1.1")

    assert len(result) == 1
    assert result[0].source_ip == "1.1.1.1"


def test_list_all_respects_limit(repository: IncidentRepository) -> None:
    """list_all deve respeitar o parâmetro limit."""
    incidents = [make_incident(f"1.1.1.{i}", float(i)) for i in range(5)]
    repository.save_all(incidents)

    result = repository.list_all(limit=2)

    assert len(result) == 2