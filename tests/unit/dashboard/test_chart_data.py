"""Testes unitários para as funções de agregação de dados de gráficos."""

from __future__ import annotations

from datetime import UTC, datetime

from siem.dashboard.chart_data import build_severity_distribution, build_top_source_ips
from siem.models.detection_event import DetectionEvent, DetectionSeverity
from siem.models.incident import Incident
from siem.models.risk_score import RiskScore

BASE_TIME = datetime(2024, 1, 1, 12, 0, 0, tzinfo=UTC)


def make_incident(source_ip: str, score: float, severity: DetectionSeverity) -> Incident:
    event = DetectionEvent(
        detector_name="brute_force_detector",
        severity=severity,
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


def test_severity_distribution_empty_incidents_returns_empty_list() -> None:
    """Sem incidentes, a distribuição deve ser uma lista vazia."""
    assert build_severity_distribution([]) == []


def test_severity_distribution_counts_by_highest_severity() -> None:
    """Deve contar corretamente incidentes agrupados por severidade."""
    incidents = [
        make_incident("1.1.1.1", 90.0, DetectionSeverity.CRITICAL),
        make_incident("2.2.2.2", 50.0, DetectionSeverity.HIGH),
        make_incident("3.3.3.3", 45.0, DetectionSeverity.HIGH),
    ]

    distribution = build_severity_distribution(incidents)

    counts = {item.severity: item.count for item in distribution}
    assert counts["critical"] == 1
    assert counts["high"] == 2


def test_severity_distribution_follows_fixed_order() -> None:
    """A ordem retornada deve ser sempre critical -> high -> medium -> low."""
    incidents = [
        make_incident("1.1.1.1", 20.0, DetectionSeverity.LOW),
        make_incident("2.2.2.2", 90.0, DetectionSeverity.CRITICAL),
    ]

    distribution = build_severity_distribution(incidents)

    assert [item.severity for item in distribution] == ["critical", "low"]


def test_severity_distribution_percentage_relative_to_max() -> None:
    """A porcentagem do grupo com mais ocorrências deve ser 100%."""
    incidents = [
        make_incident("1.1.1.1", 90.0, DetectionSeverity.CRITICAL),
        make_incident("2.2.2.2", 50.0, DetectionSeverity.HIGH),
        make_incident("3.3.3.3", 45.0, DetectionSeverity.HIGH),
    ]

    distribution = build_severity_distribution(incidents)

    high_item = next(item for item in distribution if item.severity == "high")
    assert high_item.percentage == 100.0


def test_top_source_ips_empty_incidents_returns_empty_list() -> None:
    """Sem incidentes, o ranking deve ser uma lista vazia."""
    assert build_top_source_ips([]) == []


def test_top_source_ips_sorted_by_score_descending() -> None:
    """O ranking deve vir ordenado do maior para o menor score."""
    incidents = [
        make_incident("low-risk", 30.0, DetectionSeverity.MEDIUM),
        make_incident("high-risk", 90.0, DetectionSeverity.CRITICAL),
    ]

    top_ips = build_top_source_ips(incidents)

    assert top_ips[0].source_ip == "high-risk"
    assert top_ips[1].source_ip == "low-risk"


def test_top_source_ips_respects_limit() -> None:
    """O ranking não deve exceder o limite configurado."""
    incidents = [
        make_incident(f"ip-{i}", float(i), DetectionSeverity.MEDIUM) for i in range(10)
    ]

    top_ips = build_top_source_ips(incidents, limit=3)

    assert len(top_ips) == 3


def test_top_source_ips_highest_score_has_full_percentage() -> None:
    """O IP com maior score deve ter percentage igual a 100."""
    incidents = [
        make_incident("1.1.1.1", 80.0, DetectionSeverity.HIGH),
        make_incident("2.2.2.2", 40.0, DetectionSeverity.MEDIUM),
    ]

    top_ips = build_top_source_ips(incidents)

    assert top_ips[0].percentage == 100.0