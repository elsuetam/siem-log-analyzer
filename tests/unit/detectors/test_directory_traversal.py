"""Testes unitários para DirectoryTraversalDetector."""

from __future__ import annotations

from datetime import UTC, datetime

import pytest

from siem.detectors.directory_traversal import DirectoryTraversalDetector
from siem.models.log_entry import LogEntry

BASE_TIME = datetime(2024, 1, 1, 12, 0, 0, tzinfo=UTC)


def make_entry(source_ip: str, path: str) -> LogEntry:
    return LogEntry(
        timestamp=BASE_TIME,
        source_ip=source_ip,
        method="GET",
        path=path,
        protocol="HTTP/1.1",
        status_code=200,
        bytes_sent=100,
        raw_line="raw",
    )


@pytest.fixture
def detector() -> DirectoryTraversalDetector:
    return DirectoryTraversalDetector()


@pytest.mark.parametrize(
    "path",
    [
        "/download?file=../../../../etc/passwd",
        "/files?path=..%2f..%2f..%2fetc%2fpasswd",
        "/view?doc=..\\..\\windows\\win.ini",
        "/get?f=....//....//boot.ini",
    ],
)
def test_detects_common_traversal_patterns(
    detector: DirectoryTraversalDetector, path: str
) -> None:
    """Padrões comuns de directory traversal devem ser detectados."""
    entries = [make_entry("1.1.1.1", path)]

    events = detector.detect(entries)

    assert len(events) == 1
    assert events[0].source_ip == "1.1.1.1"
    assert events[0].severity.value == "high"


def test_does_not_flag_normal_file_paths(detector: DirectoryTraversalDetector) -> None:
    """Paths normais de arquivo não devem gerar detecção."""
    entries = [
        make_entry("1.1.1.1", "/images/logo.png"),
        make_entry("1.1.1.1", "/documents/report.pdf"),
    ]

    events = detector.detect(entries)

    assert events == []


def test_aggregates_multiple_matches_from_same_ip(detector: DirectoryTraversalDetector) -> None:
    """Múltiplas tentativas do mesmo IP devem virar um único DetectionEvent agregado."""
    entries = [
        make_entry("1.1.1.1", "/a?f=../../etc/passwd"),
        make_entry("1.1.1.1", "/b?f=../../../win.ini"),
    ]

    events = detector.detect(entries)

    assert len(events) == 1
    assert events[0].occurrence_count == 2


def test_detection_event_includes_mitre_technique(detector: DirectoryTraversalDetector) -> None:
    """O evento gerado deve incluir a técnica MITRE ATT&CK correspondente (T1190)."""
    entries = [make_entry("1.1.1.1", "/a?f=../../etc/passwd")]

    events = detector.detect(entries)

    assert events[0].mitre_technique_id == "T1190"