"""Testes unitários para SqlInjectionDetector."""

from __future__ import annotations

from datetime import UTC, datetime

import pytest

from siem.detectors.sql_injection import SqlInjectionDetector
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
def detector() -> SqlInjectionDetector:
    return SqlInjectionDetector()


@pytest.mark.parametrize(
    "path",
    [
        "/login?user=admin' OR '1'='1",
        "/products?id=1 UNION SELECT username,password FROM users",
        "/search?q=test'; DROP TABLE users;--",
        "/item?id=5%27%20OR%20%271%27%3D%271",
    ],
)
def test_detects_common_sqli_patterns(detector: SqlInjectionDetector, path: str) -> None:
    """Padrões comuns de SQL Injection devem ser detectados."""
    entries = [make_entry("1.1.1.1", path)]

    events = detector.detect(entries)

    assert len(events) == 1
    assert events[0].source_ip == "1.1.1.1"
    assert events[0].severity.value == "critical"


def test_does_not_flag_normal_query_parameters(detector: SqlInjectionDetector) -> None:
    """Paths normais, sem padrões suspeitos, não devem gerar detecção."""
    entries = [
        make_entry("1.1.1.1", "/products?category=electronics&sort=price"),
        make_entry("1.1.1.1", "/users/profile?id=42"),
    ]

    events = detector.detect(entries)

    assert events == []


def test_aggregates_multiple_matches_from_same_ip(detector: SqlInjectionDetector) -> None:
    """Múltiplas tentativas do mesmo IP devem virar um único DetectionEvent agregado."""
    entries = [
        make_entry("1.1.1.1", "/a?id=1' OR '1'='1"),
        make_entry("1.1.1.1", "/b?id=2' OR '1'='1"),
    ]

    events = detector.detect(entries)

    assert len(events) == 1
    assert events[0].occurrence_count == 2


def test_tracks_different_ips_independently(detector: SqlInjectionDetector) -> None:
    """IPs diferentes com padrões suspeitos devem gerar eventos separados."""
    entries = [
        make_entry("1.1.1.1", "/a?id=1' OR '1'='1"),
        make_entry("2.2.2.2", "/b UNION SELECT * FROM users"),
    ]

    events = detector.detect(entries)

    assert len(events) == 2


def test_detection_event_includes_mitre_technique(detector: SqlInjectionDetector) -> None:
    """O evento gerado deve incluir a técnica MITRE ATT&CK correspondente (T1190)."""
    entries = [make_entry("1.1.1.1", "/a?id=1' OR '1'='1")]

    events = detector.detect(entries)

    assert events[0].mitre_technique_id == "T1190"