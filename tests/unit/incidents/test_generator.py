"""Testes unitários para generate_incidents."""

from __future__ import annotations

from datetime import UTC, datetime

from siem.incidents.generator import generate_incidents
from siem.models.detection_event import DetectionEvent, DetectionSeverity
from siem.models.incident import IncidentStatus
from siem.models.risk_score import RiskScore

BASE_TIME = datetime(2024, 1, 1, 12, 0, 0, tzinfo=UTC)


def make_risk_score(
    source_ip: str, score: float, detector_name: str = "brute_force_detector"
) -> RiskScore:
    event = DetectionEvent(
        detector_name=detector_name,
        severity=DetectionSeverity.HIGH,
        source_ip=source_ip,
        description="evento de teste",
        first_seen=BASE_TIME,
        last_seen=BASE_TIME,
        occurrence_count=1,
    )
    return RiskScore(
        source_ip=source_ip,
        score=score,
        contributing_events=[event],
        distinct_detectors=1,
    )


def test_no_scores_produces_no_incidents() -> None:
    """Lista vazia de scores não deve gerar incidentes."""
    assert generate_incidents([], threshold=25.0) == []


def test_score_above_threshold_generates_incident() -> None:
    """Um score acima do threshold deve gerar exatamente um incidente."""
    scores = [make_risk_score("1.1.1.1", score=50.0)]

    incidents = generate_incidents(scores, threshold=25.0)

    assert len(incidents) == 1
    assert incidents[0].source_ip == "1.1.1.1"
    assert incidents[0].risk_score == 50.0
    assert incidents[0].status == IncidentStatus.OPEN


def test_score_below_threshold_does_not_generate_incident() -> None:
    """Um score abaixo do threshold não deve gerar incidente."""
    scores = [make_risk_score("1.1.1.1", score=10.0)]

    incidents = generate_incidents(scores, threshold=25.0)

    assert incidents == []


def test_score_exactly_at_threshold_generates_incident() -> None:
    """Um score exatamente igual ao threshold deve gerar incidente (limite inclusivo)."""
    scores = [make_risk_score("1.1.1.1", score=25.0)]

    incidents = generate_incidents(scores, threshold=25.0)

    assert len(incidents) == 1


def test_only_qualifying_scores_generate_incidents() -> None:
    """Apenas os scores que atingem o threshold devem virar incidentes; outros são ignorados."""
    scores = [
        make_risk_score("high-risk", score=80.0),
        make_risk_score("low-risk", score=5.0),
    ]

    incidents = generate_incidents(scores, threshold=25.0)

    assert len(incidents) == 1
    assert incidents[0].source_ip == "high-risk"


def test_incidents_are_sorted_by_score_descending() -> None:
    """Os incidentes gerados devem vir ordenados do maior para o menor score."""
    scores = [
        make_risk_score("medium-risk", score=40.0),
        make_risk_score("high-risk", score=90.0),
    ]

    incidents = generate_incidents(scores, threshold=25.0)

    assert incidents[0].source_ip == "high-risk"
    assert incidents[1].source_ip == "medium-risk"


def test_each_incident_has_unique_id() -> None:
    """Cada incidente gerado deve ter um incident_id único."""
    scores = [
        make_risk_score("1.1.1.1", score=50.0),
        make_risk_score("2.2.2.2", score=60.0),
    ]

    incidents = generate_incidents(scores, threshold=25.0)

    ids = {incident.incident_id for incident in incidents}
    assert len(ids) == 2


def test_incident_title_includes_detector_names() -> None:
    """O título do incidente deve mencionar o(s) detector(es) que contribuíram."""
    scores = [make_risk_score("1.1.1.1", score=50.0, detector_name="scanner_detector")]

    incidents = generate_incidents(scores, threshold=25.0)

    assert "scanner_detector" in incidents[0].title
    assert "1.1.1.1" in incidents[0].title