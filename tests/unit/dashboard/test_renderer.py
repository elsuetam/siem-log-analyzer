"""Testes unitários para DashboardRenderer."""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path

from siem.dashboard.renderer import DashboardData, DashboardRenderer
from siem.models.detection_event import DetectionEvent, DetectionSeverity
from siem.models.incident import Incident
from siem.models.risk_score import RiskScore

BASE_TIME = datetime(2024, 1, 1, 12, 0, 0, tzinfo=UTC)


def make_incident(source_ip: str, score: float) -> Incident:
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
        source_ip=source_ip,
        score=score,
        contributing_events=[event],
        distinct_detectors=1,
    )
    return Incident(
        source_ip=source_ip,
        risk_score=score,
        title=f"Incidente de teste para {source_ip}",
        risk_details=risk_score,
    )


def test_render_with_incidents_includes_incident_data() -> None:
    """O HTML gerado deve conter os dados dos incidentes passados."""
    renderer = DashboardRenderer()
    data = DashboardData(incidents=[make_incident("1.2.3.4", 75.0)])

    html = renderer.render(data)

    assert "1.2.3.4" in html
    assert "Incidente de teste para 1.2.3.4" in html
    assert "75" in html


def test_render_with_no_incidents_shows_empty_state() -> None:
    """Sem incidentes, o HTML deve exibir a mensagem de estado vazio."""
    renderer = DashboardRenderer()
    data = DashboardData(incidents=[])

    html = renderer.render(data)

    assert "Nenhum incidente identificado" in html


def test_render_produces_valid_html_structure() -> None:
    """O HTML gerado deve ter a estrutura básica de um documento válido."""
    renderer = DashboardRenderer()
    data = DashboardData(incidents=[])

    html = renderer.render(data)

    assert html.strip().startswith("<!DOCTYPE html>")
    assert "<html" in html
    assert "</html>" in html


def test_render_to_file_creates_file_with_content(tmp_path: Path) -> None:
    """render_to_file deve criar o arquivo no caminho especificado com o HTML."""
    renderer = DashboardRenderer()
    data = DashboardData(incidents=[make_incident("9.9.9.9", 50.0)])
    output_path = tmp_path / "dashboards" / "dashboard.html"

    result_path = renderer.render_to_file(data, output_path)

    assert result_path == output_path
    assert output_path.exists()
    assert "9.9.9.9" in output_path.read_text(encoding="utf-8")


def test_render_to_file_creates_missing_parent_directories(tmp_path: Path) -> None:
    """render_to_file deve criar diretórios pais que ainda não existem."""
    renderer = DashboardRenderer()
    data = DashboardData(incidents=[])
    output_path = tmp_path / "does" / "not" / "exist" / "dashboard.html"

    renderer.render_to_file(data, output_path)

    assert output_path.exists()