"""Aplicação FastAPI que expõe o pipeline do SIEM via HTTP."""

from __future__ import annotations

from datetime import UTC, datetime

from fastapi import FastAPI, HTTPException

from siem.api.schemas import AnalyzeResponse, HealthResponse, IncidentsResponse
from siem.config.settings import get_settings
from siem.dashboard.renderer import DashboardData, DashboardRenderer
from siem.main import _build_detectors, _discover_log_files, _enrich_with_geoip
from siem.models.incident import Incident
from siem.parsers.combined_log_format import CombinedLogFormatParser
from siem.pipeline import run_pipeline

app = FastAPI(
    title="SIEM / Log Analyzer API",
    description="API REST para disparar análises de log e consultar incidentes.",
    version="0.1.0",
)

# Cache simples em memória do resultado da última análise executada.
# Suficiente para um projeto de portfólio; em produção isso viraria
# persistência real (banco de dados), fora do escopo desta etapa.
_last_analysis: dict[str, object] = {"incidents": [], "analyzed_at": None}


@app.get("/health", response_model=HealthResponse)
def health() -> HealthResponse:
    """Verifica se a API está no ar."""
    return HealthResponse()


@app.post("/analyze", response_model=AnalyzeResponse)
def analyze() -> AnalyzeResponse:
    """Executa o pipeline completo sobre os arquivos de log configurados.

    Lê todos os arquivos .log do diretório configurado (SIEM_RAW_LOGS_DIR),
    roda os detectores, calcula scores de risco, gera incidentes, e também
    atualiza o dashboard HTML e o relatório PDF em disco (mesmo efeito
    colateral de rodar `python -m siem.main`).
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

    _last_analysis["incidents"] = incidents
    _last_analysis["analyzed_at"] = datetime.now(UTC).isoformat()

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
def get_incidents() -> IncidentsResponse:
    """Retorna os incidentes da última análise executada via /analyze.

    Se nenhuma análise foi executada ainda nesta sessão da API, retorna
    uma lista vazia (não é um erro — é o estado inicial esperado).
    """
    incidents: list[Incident] = _last_analysis["incidents"]  # type: ignore[assignment]
    analyzed_at: str | None = _last_analysis["analyzed_at"]  # type: ignore[assignment]
    return IncidentsResponse(incidents=incidents, analyzed_at=analyzed_at)