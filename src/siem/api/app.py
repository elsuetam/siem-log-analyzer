"""Aplicação FastAPI que expõe o pipeline do SIEM via HTTP."""

from __future__ import annotations

from fastapi import FastAPI, HTTPException

from siem.api.schemas import AnalyzeResponse, HealthResponse, IncidentsResponse
from siem.config.settings import get_settings
from siem.dashboard.renderer import DashboardData, DashboardRenderer
from siem.main import _build_detectors, _discover_log_files, _enrich_with_geoip
from siem.models.incident import Incident
from siem.parsers.combined_log_format import CombinedLogFormatParser
from siem.persistence.db import create_session_factory
from siem.persistence.repository import IncidentRepository
from siem.pipeline import run_pipeline

app = FastAPI(
    title="SIEM / Log Analyzer API",
    description="API REST para disparar análises de log e consultar incidentes.",
    version="0.1.0",
)


def _get_repository() -> IncidentRepository:
    """Constrói o repositório de incidentes a partir das settings atuais.

    Função separada (em vez de instância global) para que os testes possam
    substituí-la facilmente via monkeypatch, isolando cada teste em seu
    próprio banco.
    """
    settings = get_settings()
    session_factory = create_session_factory(settings.database_url)
    return IncidentRepository(session_factory)


@app.get("/health", response_model=HealthResponse)
def health() -> HealthResponse:
    """Verifica se a API está no ar."""
    return HealthResponse()


@app.post("/analyze", response_model=AnalyzeResponse)
def analyze() -> AnalyzeResponse:
    """Executa o pipeline completo sobre os arquivos de log configurados.

    Lê todos os arquivos .log do diretório configurado (SIEM_RAW_LOGS_DIR),
    roda os detectores, calcula scores de risco, gera incidentes, atualiza
    o dashboard HTML e persiste os incidentes no banco de dados.
    """
    settings = get_settings()
    settings.ensure_directories_exist()

    log_files = _discover_log_files(settings.raw_logs_dir, explicit_file=None)
    if not log_files:
        raise HTTPException(
            status_code=404,
            detail=f"Nenhum arquivo de log encontrado em {settings.raw_logs_dir}.",
        )

    result = run_pipeline(
        log_files=log_files,
        parser=CombinedLogFormatParser(),
        detectors=_build_detectors(settings),
        risk_threshold=settings.incident_risk_score_threshold,
        encoding=settings.file_encoding,
    )

    incidents = _enrich_with_geoip(result.incidents, settings)

    _get_repository().save_all(incidents)

    renderer = DashboardRenderer()
    renderer.render_to_file(
        DashboardData(
            incidents=incidents,
            total_entries=result.total_entries,
            total_detections=result.total_detections,
        ),
        settings.dashboards_dir / "dashboard.html",
    )

    return AnalyzeResponse(
        total_entries=result.total_entries,
        total_detections=result.total_detections,
        incidents=incidents,
    )


@app.get("/incidents", response_model=IncidentsResponse)
def list_incidents() -> IncidentsResponse:
    """Retorna os incidentes mais recentes persistidos no banco de dados."""
    incidents: list[Incident] = _get_repository().list_all()
    return IncidentsResponse(incidents=incidents)


@app.get("/incidents/{incident_id}", response_model=Incident)
def get_incident(incident_id: str) -> Incident:
    """Retorna um incidente específico pelo ID, ou 404 se não encontrado."""
    incident = _get_repository().get_by_id(incident_id)
    if incident is None:
        raise HTTPException(status_code=404, detail=f"Incidente {incident_id} não encontrado.")
    return incident