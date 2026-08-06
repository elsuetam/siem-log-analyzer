"""Testes unitários para BruteForceDetector."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest

from siem.detectors.brute_force import BruteForceDetector
from siem.models.log_entry import LogEntry

BASE_TIME = datetime(2024, 1, 1, 12, 0, 0, tzinfo=UTC)


def make_entry(
    source_ip: str,
    offset_seconds: int,
    status_code: int = 401,
    path: str = "/login",
) -> LogEntry:
    return LogEntry(
        timestamp=BASE_TIME + timedelta(seconds=offset_seconds),
        source_ip=source_ip,
        method="POST",
        path=path,
        protocol="HTTP/1.1",
        status_code=status_code,
        bytes_sent=100,
        raw_line="raw",
    )


@pytest.fixture
def detector() -> BruteForceDetector:
    return BruteForceDetector(attempts_threshold=5, window_seconds=60)


def test_detects_brute_force_within_window(detector: BruteForceDetector) -> None:
    """5 falhas de login em 60s do mesmo IP devem gerar uma detecção."""
    entries = [make_entry("1.2.3.4", offset_seconds=i * 10) for i in range(5)]

    events = detector.detect(entries)

    assert len(events) == 1
    assert events[0].source_ip == "1.2.3.4"
    assert events[0].occurrence_count == 5


def test_does_not_detect_below_threshold(detector: BruteForceDetector) -> None:
    """4 falhas (abaixo do threshold de 5) não devem gerar detecção."""
    entries = [make_entry("1.2.3.4", offset_seconds=i * 10) for i in range(4)]

    events = detector.detect(entries)

    assert events == []


def test_does_not_detect_failures_outside_window(detector: BruteForceDetector) -> None:
    """5 falhas espalhadas fora da janela de 60s não devem gerar detecção."""
    entries = [make_entry("1.2.3.4", offset_seconds=i * 100) for i in range(5)]

    events = detector.detect(entries)

    assert events == []


def test_ignores_successful_logins(detector: BruteForceDetector) -> None:
    """Requisições de login bem-sucedidas (200) não contam como falha."""
    entries = [make_entry("1.2.3.4", offset_seconds=i * 10, status_code=200) for i in range(5)]

    events = detector.detect(entries)

    assert events == []


def test_ignores_failures_on_non_login_paths(detector: BruteForceDetector) -> None:
    """Falhas 401/403 fora de endpoints de login não devem contar."""
    entries = [
        make_entry("1.2.3.4", offset_seconds=i * 10, path="/admin/dashboard")
        for i in range(5)
    ]

    events = detector.detect(entries)

    assert events == []


def test_tracks_different_ips_independently(detector: BruteForceDetector) -> None:
    """IPs diferentes devem ser avaliados independentemente."""
    entries = [make_entry("1.2.3.4", offset_seconds=i * 10) for i in range(5)]
    entries += [make_entry("5.6.7.8", offset_seconds=i * 10) for i in range(3)]

    events = detector.detect(entries)

    assert len(events) == 1
    assert events[0].source_ip == "1.2.3.4"


def test_detection_event_includes_mitre_technique(detector: BruteForceDetector) -> None:
    """O evento gerado deve incluir a técnica MITRE ATT&CK correspondente (T1110)."""
    entries = [make_entry("1.2.3.4", offset_seconds=i * 10) for i in range(5)]

    events = detector.detect(entries)

    assert events[0].mitre_technique_id == "T1110"
    assert events[0].mitre_technique_name == "Brute Force"