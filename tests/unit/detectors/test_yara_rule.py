"""Testes unitários para YaraDetector."""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path

import pytest

from siem.detectors.yara_rule import YaraDetector
from siem.models.log_entry import LogEntry

yara = pytest.importorskip("yara")

BASE_TIME = datetime(2024, 1, 1, 12, 0, 0, tzinfo=UTC)

_RULE_YARA = """
rule Test_Sqlmap_Detection
{
    strings:
        $sqlmap = "sqlmap" nocase
    condition:
        any of them
}
"""


def make_entry(source_ip: str, raw_line: str) -> LogEntry:
    return LogEntry(
        timestamp=BASE_TIME,
        source_ip=source_ip,
        method="GET",
        path="/",
        protocol="HTTP/1.1",
        status_code=200,
        bytes_sent=100,
        raw_line=raw_line,
    )


def test_detector_with_no_rules_directory_returns_empty(tmp_path: Path) -> None:
    """Se o diretório de regras não existir, o detector não deve gerar detecções."""
    detector = YaraDetector(rules_dir=tmp_path / "does-not-exist")

    events = detector.detect([make_entry("1.1.1.1", "linha normal de log")])

    assert events == []


def test_detector_matches_yara_rule(tmp_path: Path) -> None:
    """Uma linha contendo a assinatura YARA deve gerar detecção."""
    (tmp_path / "rule.yar").write_text(_RULE_YARA, encoding="utf-8")
    detector = YaraDetector(rules_dir=tmp_path)

    raw = '1.1.1.1 - - [.] "GET / HTTP/1.1" 200 100 "-" "sqlmap/1.6"'
    events = detector.detect([make_entry("1.1.1.1", raw)])

    assert len(events) == 1
    assert events[0].source_ip == "1.1.1.1"


def test_detector_does_not_match_normal_line(tmp_path: Path) -> None:
    """Uma linha sem assinaturas suspeitas não deve gerar detecção."""
    (tmp_path / "rule.yar").write_text(_RULE_YARA, encoding="utf-8")
    detector = YaraDetector(rules_dir=tmp_path)

    events = detector.detect([make_entry("1.1.1.1", "linha normal de log")])

    assert events == []