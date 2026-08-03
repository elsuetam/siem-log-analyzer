"""Ponto de entrada da aplicação SIEM / Log Analyzer."""

from __future__ import annotations

import argparse
import sys

from siem.config.settings import get_settings
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
    return parser


def run() -> int:
    """Executa a aplicação. Retorna o código de saída do processo."""
    settings = get_settings()
    setup_logging()
    settings.ensure_directories_exist()

    parser = build_arg_parser()
    parser.parse_args()

    print("SIEM / Log Analyzer inicializado.")
    print(f"Diretório de logs brutos: {settings.raw_logs_dir}")
    print(f"Diretório de dados processados: {settings.processed_dir}")
    print(f"Diretório de relatórios: {settings.reports_dir}")
    print(f"Diretório de dashboards: {settings.dashboards_dir}")
    print(f"Threshold de brute force: {settings.brute_force_attempts_threshold} tentativas "
          f"em {settings.brute_force_window_seconds}s")
    print("Pipeline de análise ainda não implementado (próximas etapas).")

    return 0


if __name__ == "__main__":
    sys.exit(run())