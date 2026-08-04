"""Testes unitários para as funções auxiliares de main.py."""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path

from siem.config.settings import Settings
from siem.detectors.brute_force import BruteForceDetector
from siem.detectors.scanner import ScannerDetector
from siem.main import _build_detectors, _discover_log_files, _print_incidents, build_arg_parser
from siem.models.detection_event import DetectionEvent, DetectionSeverity
from siem.models.incident import Incident
from siem.models.risk_score import RiskScore

BASE_TIME = datetime(2024, 1, 1, 12, 0, 0, tzinfo=UTC)


def test_build_arg_parser_accepts_log_file_argument() -> None:
    """O parser de CLI deve aceitar --log-file e convertê-lo em Path."""
    parser = build_arg_parser()

    args = parser.parse_args(["--log-file", "custom.log"])

    assert args.log_file == Path("custom.log")


def test_build_arg_parser_defaults_log_file_to_none() -> None:
    """Sem --log-file, o valor padrão deve ser None."""
    parser = build_arg_parser()

    args = parser.parse_args([])

    assert args.log_file is None


def test_discover_log_files_returns_explicit_file_when_given(tmp_path: Path) -> None:
    """Quando um arquivo explícito é passado, ele deve ser retornado diretamente."""
    explicit_file = tmp_path / "custom.log"

    result = _discover_log_files(raw_logs_dir=tmp_path, explicit_file=explicit_file)

    assert result == [explicit_file]


def test_discover_log_files_globs_directory_when_no_explicit_file(tmp_path: Path) -> None:
    """Sem arquivo explícito, deve retornar todos os .log do diretório, ordenados."""
    (tmp_path / "b.log").write_text("", encoding="utf-8")
    (tmp_path / "a.log").write_text("", encoding="utf-8")
    (tmp_path / "ignored.txt").write_text("", encoding="utf-8")

    result = _discover_log_files(raw_logs_dir=tmp_path, explicit_file=None)

    assert result == [tmp_path / "a.log", tmp_path / "b.log"]


def test_build_detectors_returns_brute_force_and_scanner() -> None:
    """_build_detectors deve montar exatamente os detectores esperados a partir das settings."""
    settings = Settings(_env_file=None)

    detectors = _build_detectors(settings)

    assert len(detectors) == 2
    assert isinstance(detectors[0], BruteForceDetector)
    assert isinstance(detectors[1], ScannerDetector)


def _make_incident(source_ip: str, score: float) -> Incident:
    event = DetectionEvent(
        detector_name="brute_force_detector",
        severity=DetectionSeverity.HIGH,
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


def test_print_incidents_with_empty_list_shows_no_incidents_message(capsys) -> None:  # type: ignore[no-untyped-def]
    """Sem incidentes, deve imprimir a mensagem de 'nenhum incidente'."""
    _print_incidents([])

    captured = capsys.readouterr()
    assert "Nenhum incidente gerado" in captured.out


def test_print_incidents_with_data_prints_titles_and_ids(capsys) -> None:  # type: ignore[no-untyped-def]
    """Com incidentes, deve imprimir título, score e ID de cada um."""
    incident = _make_incident("1.2.3.4", 50.0)

    _print_incidents([incident])

    captured = capsys.readouterr()
    assert "1.2.3.4" in captured.out
    assert incident.incident_id in captured.out