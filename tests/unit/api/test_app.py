"""Testes unitários para a API REST (siem.api.app)."""

from __future__ import annotations

from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from siem.api.app import app
from siem.config.settings import Settings


@pytest.fixture
def client() -> TestClient:
    return TestClient(app)


def test_health_returns_ok(client: TestClient) -> None:
    """GET /health deve retornar status 200 com {'status': 'ok'}."""
    response = client.get("/health")

    assert response.status_code == 200
    assert response.json() == {"status": "ok"}


def test_incidents_returns_empty_before_any_analysis(
    client: TestClient, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """GET /incidents em um banco vazio (isolado) deve retornar lista vazia."""
    test_settings = Settings(
        _env_file=None,
        database_url=f"sqlite:///{tmp_path / 'test.db'}",
    )
    monkeypatch.setattr("siem.api.app.get_settings", lambda: test_settings)

    response = client.get("/incidents")

    assert response.status_code == 200
    data = response.json()
    assert data["incidents"] == []


def test_analyze_returns_404_when_no_log_files_exist(
    client: TestClient, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """POST /analyze deve retornar 404 se não houver arquivos de log configurados."""
    empty_dir = tmp_path / "empty_logs"
    empty_dir.mkdir()

    test_settings = Settings(
        _env_file=None,
        raw_logs_dir=empty_dir,
        database_url=f"sqlite:///{tmp_path / 'test.db'}",
    )
    monkeypatch.setattr("siem.api.app.get_settings", lambda: test_settings)

    response = client.post("/analyze")

    assert response.status_code == 404


def test_analyze_processes_logs_and_returns_incidents(
    client: TestClient, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """POST /analyze deve processar um log real e retornar os incidentes gerados."""
    raw_logs_dir = tmp_path / "raw_logs"
    raw_logs_dir.mkdir()
    output_dir = tmp_path / "output"

    brute_force_lines = "\n".join(
        f'10.0.0.9 - - [10/Oct/2023:13:55:{i:02d} +0000] '
        f'"POST /login HTTP/1.1" 401 100 "-" "-"'
        for i in range(6)
    )
    (raw_logs_dir / "access.log").write_text(brute_force_lines + "\n", encoding="utf-8")

    test_settings = Settings(
        _env_file=None,
        raw_logs_dir=raw_logs_dir,
        output_dir=output_dir,
        reports_dir=output_dir / "reports",
        dashboards_dir=output_dir / "dashboards",
        database_url=f"sqlite:///{tmp_path / 'test.db'}",
    )
    monkeypatch.setattr("siem.api.app.get_settings", lambda: test_settings)

    response = client.post("/analyze")

    assert response.status_code == 200
    data = response.json()
    assert data["total_entries"] == 6
    assert len(data["incidents"]) == 1
    assert data["incidents"][0]["source_ip"] == "10.0.0.9"


def test_incidents_reflects_last_analysis(
    client: TestClient, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """GET /incidents deve refletir o resultado do /analyze mais recente."""
    raw_logs_dir = tmp_path / "raw_logs"
    raw_logs_dir.mkdir()
    output_dir = tmp_path / "output"

    brute_force_lines = "\n".join(
        f'10.0.0.9 - - [10/Oct/2023:13:55:{i:02d} +0000] '
        f'"POST /login HTTP/1.1" 401 100 "-" "-"'
        for i in range(6)
    )
    (raw_logs_dir / "access.log").write_text(brute_force_lines + "\n", encoding="utf-8")

    test_settings = Settings(
        _env_file=None,
        raw_logs_dir=raw_logs_dir,
        output_dir=output_dir,
        reports_dir=output_dir / "reports",
        dashboards_dir=output_dir / "dashboards",
        database_url=f"sqlite:///{tmp_path / 'test.db'}",
    )
    monkeypatch.setattr("siem.api.app.get_settings", lambda: test_settings)

    client.post("/analyze")
    response = client.get("/incidents")

    assert response.status_code == 200
    data = response.json()
    assert len(data["incidents"]) == 1