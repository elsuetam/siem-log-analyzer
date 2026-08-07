"""Testes unitários para SigmaRuleDetector."""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path

from siem.detectors.sigma_rule import SigmaRuleDetector
from siem.models.log_entry import LogEntry

BASE_TIME = datetime(2024, 1, 1, 12, 0, 0, tzinfo=UTC)

_RULE_YAML = """
title: Acesso negado a área administrativa
id: test-rule-001
severity: high
detection:
  selection:
    path_contains: "/admin"
    status_code: 403
  condition: selection
"""


def make_entry(source_ip: str, path: str, status_code: int) -> LogEntry:
    return LogEntry(
        timestamp=BASE_TIME,
        source_ip=source_ip,
        method="GET",
        path=path,
        protocol="HTTP/1.1",
        status_code=status_code,
        bytes_sent=100,
        raw_line="raw",
    )


def test_detector_with_no_rules_directory_returns_empty(tmp_path: Path) -> None:
    """Se o diretório de regras não existir, o detector não deve gerar detecções."""
    detector = SigmaRuleDetector(rules_dir=tmp_path / "does-not-exist")

    events = detector.detect([make_entry("1.1.1.1", "/admin/panel", 403)])

    assert events == []


def test_detector_matches_rule_condition(tmp_path: Path) -> None:
    """Uma entrada que satisfaz a seleção da regra deve gerar detecção."""
    (tmp_path / "rule.yml").write_text(_RULE_YAML, encoding="utf-8")
    detector = SigmaRuleDetector(rules_dir=tmp_path)

    events = detector.detect([make_entry("1.1.1.1", "/admin/panel", 403)])

    assert len(events) == 1
    assert events[0].source_ip == "1.1.1.1"
    assert events[0].severity.value == "high"


def test_detector_does_not_match_when_condition_partially_fails(tmp_path: Path) -> None:
    """Uma entrada que satisfaz só parte da seleção não deve gerar detecção."""
    (tmp_path / "rule.yml").write_text(_RULE_YAML, encoding="utf-8")
    detector = SigmaRuleDetector(rules_dir=tmp_path)

    # path bate, mas status_code não é 403
    events = detector.detect([make_entry("1.1.1.1", "/admin/panel", 200)])

    assert events == []


def test_detector_skips_malformed_rule_file(tmp_path: Path) -> None:
    """Uma regra malformada deve ser ignorada, sem quebrar o carregamento das demais."""
    (tmp_path / "broken.yml").write_text("not: valid: : yaml: [", encoding="utf-8")
    (tmp_path / "good.yml").write_text(_RULE_YAML, encoding="utf-8")

    detector = SigmaRuleDetector(rules_dir=tmp_path)
    events = detector.detect([make_entry("1.1.1.1", "/admin/panel", 403)])

    assert len(events) == 1