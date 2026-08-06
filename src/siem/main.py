"""Ponto de entrada da aplicação SIEM / Log Analyzer."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from siem.config.settings import Settings, get_settings
from siem.dashboard.renderer import DashboardData, DashboardRenderer
from siem.detectors.base import BaseDetector
from siem.detectors.brute_force import BruteForceDetector
from siem.detectors.directory_traversal import DirectoryTraversalDetector
from siem.detectors.scanner import ScannerDetector
from siem.detectors.sql_injection import SqlInjectionDetector
from siem.enrichment.geoip import GeoIPEnricher
from siem.models.incident import Incident
from siem.parsers.combined_log_format import CombinedLogFormatParser
from siem.pipeline import run_pipeline
from siem.utils.logging_config import setup_logging


def build_arg_parser() -> argparse.ArgumentParser:
    """Constrói o parser de argumentos de linha de comando."""
    parser = argparse.ArgumentParser(
        prog="siem",
        description="SIEM / Log Analyzer - análise de logs e detecção de ameaças.",
    )
    parser.add_argument(
        "--version",
        action="version",
        version="siem-log-analyzer 0.1.0",
    )
    parser.add_argument(
        "--log-file",
        type=Path,
        default=None,
        help="Caminho de um arquivo de log específico. Se omitido, processa "
        "todos os arquivos .log encontrados no diretório de logs brutos.",
    )
    return parser


def _discover_log_files(raw_logs_dir: Path, explicit_file: Path | None) -> list[Path]:
    """Determina quais arquivos de log processar."""
    if explicit_file is not None:
        return [explicit_file]
    return sorted(raw_logs_dir.glob("*.log"))


def _build_detectors(settings: Settings) -> list[BaseDetector]:
    """Instancia os detectores configurados a partir das settings da aplicação."""
    return [
        BruteForceDetector(
            attempts_threshold=settings.brute_force_attempts_threshold,
            window_seconds=settings.brute_force_window_seconds,
        ),
        ScannerDetector(
            requests_threshold=settings.scanner_requests_threshold,
            window_seconds=settings.scanner_window_seconds,
        ),
        SqlInjectionDetector(),
        DirectoryTraversalDetector(),
    ]


def _enrich_with_geoip(incidents: list[Incident], settings: Settings) -> list[Incident]:
    """Enriquece os incidentes com dados de geolocalização, se habilitado nas settings.

    Retorna a lista original sem modificação se enable_geoip estiver desligado
    ou se não houver incidentes — evita chamadas de rede desnecessárias.
    """
    if not settings.enable_geoip or not incidents:
        return incidents

    enricher = GeoIPEnricher(timeout_seconds=settings.geoip_timeout_seconds)
    geo_by_ip = enricher.enrich([incident.source_ip for incident in incidents])

    return [
        incident.model_copy(update={"geo_location": geo_by_ip.get(incident.source_ip)})
        for incident in incidents
    ]


def _print_incidents(incidents: list[Incident]) -> None:
    """Exibe um resumo legível dos incidentes gerados no terminal."""
    if not incidents:
        print("Nenhum incidente gerado — nenhum IP atingiu o threshold de risco configurado.")
        return

    print(f"\n{len(incidents)} incidente(s) gerado(s):\n")
    for incident in incidents:
        print(f"  [{incident.risk_score:.0f}] {incident.title}")
        location = incident.geo_location
        if location is not None and not location.is_private and location.country:
            print(f"       Local: {location.city or '?'}, {location.country}")
        print(f"       ID: {incident.incident_id} | Status: {incident.status.value}\n")


def run() -> int:
    """Executa a aplicação. Retorna o código de saída do processo."""
    settings = get_settings()
    setup_logging()
    settings.ensure_directories_exist()

    arg_parser = build_arg_parser()
    args = arg_parser.parse_args()

    log_files = _discover_log_files(settings.raw_logs_dir, args.log_file)
    if not log_files:
        print(f"Nenhum arquivo de log encontrado em {settings.raw_logs_dir}.")
        print("Use --log-file para especificar um arquivo, ou adicione arquivos .log ao diretório.")
        return 1

    print(f"Processando {len(log_files)} arquivo(s) de log...")

    result = run_pipeline(
        log_files=log_files,
        parser=CombinedLogFormatParser(),
        detectors=_build_detectors(settings),
        risk_threshold=settings.incident_risk_score_threshold,
        encoding=settings.file_encoding,
    )

    incidents = _enrich_with_geoip(result.incidents, settings)

    _print_incidents(incidents)

    dashboard_path = settings.dashboards_dir / "dashboard.html"
    renderer = DashboardRenderer()
    renderer.render_to_file(
        DashboardData(
            incidents=incidents,
            total_entries=result.total_entries,
            total_detections=result.total_detections,
        ),
        dashboard_path,
    )
    print(f"Dashboard salvo em: {dashboard_path.resolve()}")

    return 0


if __name__ == "__main__":
    sys.exit(run())