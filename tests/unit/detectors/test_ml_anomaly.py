"""Testes unitários para MLAnomalyDetector."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest

from siem.detectors.ml_anomaly import MLAnomalyDetector
from siem.models.log_entry import LogEntry

pytest.importorskip("sklearn")

BASE_TIME = datetime(2024, 1, 1, 12, 0, 0, tzinfo=UTC)


def make_entries_for_ip(
    source_ip: str,
    count: int,
    status_code: int = 200,
    distinct_paths: int = 3,
) -> list[LogEntry]:
    """Gera `count` entradas 'normais' para um IP, variando entre `distinct_paths` paths."""
    return [
        LogEntry(
            timestamp=BASE_TIME + timedelta(seconds=i),
            source_ip=source_ip,
            method="GET",
            path=f"/page-{i % distinct_paths}",
            protocol="HTTP/1.1",
            status_code=status_code,
            bytes_sent=500,
            raw_line="raw",
        )
        for i in range(count)
    ]


@pytest.fixture
def detector() -> MLAnomalyDetector:
    return MLAnomalyDetector(contamination=0.15, min_ips_required=5, random_state=42)


def test_detector_skips_when_below_min_ips(detector: MLAnomalyDetector) -> None:
    """Com menos IPs distintos que o mínimo configurado, não deve haver detecção."""
    entries = make_entries_for_ip("1.1.1.1", count=10)  # só 1 IP distinto

    events = detector.detect(entries)

    assert events == []


def test_detector_finds_outlier_among_normal_traffic(detector: MLAnomalyDetector) -> None:
    """Um IP com comportamento muito destoante do grupo deve ser sinalizado."""
    entries: list[LogEntry] = []
    # 9 IPs com comportamento "normal" e homogêneo (poucas requisições, poucos paths)
    for i in range(9):
        entries.extend(make_entries_for_ip(f"10.0.0.{i}", count=5, distinct_paths=2))

    # 1 IP com comportamento extremamente destoante (muitas requisições, muitos paths, muitos erros)
    outlier_entries = [
        LogEntry(
            timestamp=BASE_TIME + timedelta(seconds=i),
            source_ip="99.99.99.99",
            method="GET",
            path=f"/very-different-path-{i}",
            protocol="HTTP/1.1",
            status_code=500,
            bytes_sent=50000,
            raw_line="raw",
        )
        for i in range(200)
    ]
    entries.extend(outlier_entries)

    events = detector.detect(entries)

    detected_ips = {event.source_ip for event in events}
    assert "99.99.99.99" in detected_ips


def test_detector_does_not_flag_homogeneous_traffic(detector: MLAnomalyDetector) -> None:
    """Se todos os IPs se comportam de forma parecida, poucos ou nenhum deve ser sinalizado."""
    entries: list[LogEntry] = []
    for i in range(10):
        entries.extend(make_entries_for_ip(f"10.0.0.{i}", count=5, distinct_paths=2))

    events = detector.detect(entries)

    # Com tráfego homogêneo, o número de anomalias deve ser pequeno (proporcional a contamination)
    assert len(events) <= 2


def test_detector_name_is_ml_anomaly_detector(detector: MLAnomalyDetector) -> None:
    """O nome do detector deve ser 'ml_anomaly_detector'."""
    assert detector.name == "ml_anomaly_detector"