"""Testes unitários para ScannerDetector."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest

from siem.detectors.scanner import ScannerDetector
from siem.models.log_entry import LogEntry

BASE_TIME = datetime(2024, 1, 1, 12, 0, 0, tzinfo=UTC)


def make_entry(source_ip: str, offset_ms: int, path: str) -> LogEntry:
    return LogEntry(
        timestamp=BASE_TIME + timedelta(milliseconds=offset_ms),
        source_ip=source_ip,
        method="GET",
        path=path,
        protocol="HTTP/1.1",
        status_code=404,
        bytes_sent=0,
        raw_line="raw",
    )


@pytest.fixture
def detector() -> ScannerDetector:
    return ScannerDetector(requests_threshold=20, window_seconds=10)


def test_detects_scanning_within_window(detector: ScannerDetector) -> None:
    """20 paths distintos em menos de 10s do mesmo IP devem gerar uma detecção."""
    entries = [make_entry("9.9.9.9", offset_ms=i * 400, path=f"/path-{i}") for i in range(20)]

    events = detector.detect(entries)

    assert len(events) == 1
    assert events[0].source_ip == "9.9.9.9"
    assert events[0].occurrence_count == 20


def test_does_not_detect_below_threshold(detector: ScannerDetector) -> None:
    """19 paths distintos (abaixo do threshold) não devem gerar detecção."""
    entries = [make_entry("9.9.9.9", offset_ms=i * 400, path=f"/path-{i}") for i in range(19)]

    events = detector.detect(entries)

    assert events == []


def test_repeated_same_path_does_not_count_as_scanning(detector: ScannerDetector) -> None:
    """Requisições repetidas ao mesmo path não devem contar como scanning."""
    entries = [make_entry("9.9.9.9", offset_ms=i * 400, path="/same-page") for i in range(25)]

    events = detector.detect(entries)

    assert events == []


def test_paths_outside_window_do_not_count_together(detector: ScannerDetector) -> None:
    """Paths espalhados além da janela de 10s não devem ser agrupados na mesma detecção."""
    entries = [make_entry("9.9.9.9", offset_ms=i * 700, path=f"/path-{i}") for i in range(20)]

    events = detector.detect(entries)

    assert events == []


def test_detection_event_includes_mitre_technique(detector: ScannerDetector) -> None:
    """O evento gerado deve incluir a técnica MITRE ATT&CK correspondente (T1595)."""
    entries = [make_entry("9.9.9.9", offset_ms=i * 400, path=f"/path-{i}") for i in range(20)]

    events = detector.detect(entries)

    assert events[0].mitre_technique_id == "T1595"