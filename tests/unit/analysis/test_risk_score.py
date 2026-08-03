"""Testes unitários para calculate_risk_scores."""

from __future__ import annotations

from datetime import UTC, datetime

from siem.analysis.risk_score import calculate_risk_scores
from siem.models.detection_event import DetectionEvent, DetectionSeverity

BASE_TIME = datetime(2024, 1, 1, 12, 0, 0, tzinfo=UTC)


def make_event(
    source_ip: str,
    detector_name: str,
    severity: DetectionSeverity,
) -> DetectionEvent:
    return DetectionEvent(
        detector_name=detector_name,
        severity=severity,
        source_ip=source_ip,
        description="evento de teste",
        first_seen=BASE_TIME,
        last_seen=BASE_TIME,
        occurrence_count=1,
    )


def test_empty_detections_returns_empty_list() -> None:
    """Nenhuma detecção deve resultar em nenhum score."""
    assert calculate_risk_scores([]) == []


def test_single_event_produces_score_matching_severity_weight() -> None:
    """Um único evento HIGH deve gerar score igual ao peso de HIGH (sem bônus)."""
    events = [make_event("1.1.1.1", "brute_force_detector", DetectionSeverity.HIGH)]

    scores = calculate_risk_scores(events)

    assert len(scores) == 1
    assert scores[0].source_ip == "1.1.1.1"
    assert scores[0].score == 30.0
    assert scores[0].distinct_detectors == 1


def test_multiple_events_same_detector_sum_without_diversity_bonus() -> None:
    """Múltiplos eventos do MESMO detector somam pesos, sem bônus de diversidade."""
    events = [
        make_event("1.1.1.1", "brute_force_detector", DetectionSeverity.HIGH),
        make_event("1.1.1.1", "brute_force_detector", DetectionSeverity.HIGH),
    ]

    scores = calculate_risk_scores(events)

    assert scores[0].score == 60.0
    assert scores[0].distinct_detectors == 1


def test_events_from_different_detectors_add_diversity_bonus() -> None:
    """Eventos de detectores DIFERENTES para o mesmo IP recebem bônus de diversidade."""
    events = [
        make_event("1.1.1.1", "brute_force_detector", DetectionSeverity.HIGH),
        make_event("1.1.1.1", "scanner_detector", DetectionSeverity.MEDIUM),
    ]

    scores = calculate_risk_scores(events)

    # 30 (HIGH) + 15 (MEDIUM) + 10 (bônus de 1 detector extra) = 55
    assert scores[0].score == 55.0
    assert scores[0].distinct_detectors == 2


def test_score_is_capped_at_max_value() -> None:
    """O score nunca deve ultrapassar 100, mesmo com muitos eventos acumulados."""
    events = [
        make_event("1.1.1.1", "brute_force_detector", DetectionSeverity.CRITICAL)
        for _ in range(5)
    ]

    scores = calculate_risk_scores(events)

    assert scores[0].score == 100.0


def test_different_ips_are_scored_independently() -> None:
    """IPs diferentes devem ter scores calculados de forma independente."""
    events = [
        make_event("1.1.1.1", "brute_force_detector", DetectionSeverity.CRITICAL),
        make_event("2.2.2.2", "scanner_detector", DetectionSeverity.LOW),
    ]

    scores = calculate_risk_scores(events)

    assert len(scores) == 2
    ip_scores = {s.source_ip: s.score for s in scores}
    assert ip_scores["1.1.1.1"] == 50.0
    assert ip_scores["2.2.2.2"] == 5.0


def test_results_are_sorted_by_score_descending() -> None:
    """A lista de scores deve vir ordenada do maior para o menor."""
    events = [
        make_event("low-risk-ip", "scanner_detector", DetectionSeverity.LOW),
        make_event("high-risk-ip", "brute_force_detector", DetectionSeverity.CRITICAL),
    ]

    scores = calculate_risk_scores(events)

    assert scores[0].source_ip == "high-risk-ip"
    assert scores[1].source_ip == "low-risk-ip"