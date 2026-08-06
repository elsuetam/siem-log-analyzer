"""Testes unitários para PDFReportGenerator."""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path

from pypdf import PdfReader

from siem.models.detection_event import DetectionEvent, DetectionSeverity
from siem.models.incident import Incident
from siem.models.risk_score import RiskScore
from siem.reports.pdf_report import PDFReportGenerator

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
        source_ip=source_ip,
        risk_score=score,
        title=f"Incidente de teste para {source_ip}",
        risk_details=risk_score,
    )


def _extract_text(pdf_path: Path) -> str:
    reader = PdfReader(str(pdf_path))
    return "\n".join(page.extract_text() for page in reader.pages)


def test_generate_creates_valid_pdf_file(tmp_path: Path) -> None:
    """generate() deve criar um arquivo PDF válido e legível."""
    generator = PDFReportGenerator()
    output_path = tmp_path / "report.pdf"

    result_path = generator.generate(
        incidents=[], output_path=output_path, total_entries=10, total_detections=0
    )

    assert result_path == output_path
    assert output_path.exists()
    assert output_path.stat().st_size > 0
    PdfReader(str(output_path))  # não deve levantar exceção ao abrir


def test_generate_creates_missing_parent_directories(tmp_path: Path) -> None:
    """generate() deve criar diretórios pais que ainda não existem."""
    generator = PDFReportGenerator()
    output_path = tmp_path / "does" / "not" / "exist" / "report.pdf"

    generator.generate(
        incidents=[], output_path=output_path, total_entries=0, total_detections=0
    )

    assert output_path.exists()


def test_generate_includes_summary_counters(tmp_path: Path) -> None:
    """O PDF deve conter os contadores de resumo passados."""
    generator = PDFReportGenerator()
    output_path = tmp_path / "report.pdf"

    generator.generate(
        incidents=[], output_path=output_path, total_entries=42, total_detections=7
    )

    text = _extract_text(output_path)
    assert "42" in text
    assert "7" in text


def test_generate_includes_incident_details(tmp_path: Path) -> None:
    """O PDF deve conter o IP e o título de cada incidente."""
    generator = PDFReportGenerator()
    output_path = tmp_path / "report.pdf"
    incident = make_incident("9.9.9.9", 75.0, DetectionSeverity.CRITICAL)

    generator.generate(
        incidents=[incident], output_path=output_path, total_entries=5, total_detections=1
    )

    text = _extract_text(output_path)
    assert "9.9.9.9" in text
    assert "Incidente de teste para 9.9.9.9" in text


def test_generate_with_no_incidents_shows_empty_message(tmp_path: Path) -> None:
    """Sem incidentes, o PDF deve indicar isso claramente no texto."""
    generator = PDFReportGenerator()
    output_path = tmp_path / "report.pdf"

    generator.generate(
        incidents=[], output_path=output_path, total_entries=0, total_detections=0
    )

    text = _extract_text(output_path)
    assert "Nenhum incidente" in text


def test_generate_orders_incidents_by_score_descending(tmp_path: Path) -> None:
    """Incidentes devem aparecer no PDF ordenados do maior para o menor score."""
    generator = PDFReportGenerator()
    output_path = tmp_path / "report.pdf"
    incidents = [
        make_incident("low-risk", 20.0, DetectionSeverity.LOW),
        make_incident("high-risk", 90.0, DetectionSeverity.CRITICAL),
    ]

    generator.generate(
        incidents=incidents, output_path=output_path, total_entries=2, total_detections=2
    )

    text = _extract_text(output_path)
    assert text.index("high-risk") < text.index("low-risk")