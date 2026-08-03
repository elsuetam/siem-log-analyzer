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
    setup_logging()
    settings = get_settings()

    parser = build_arg_parser()
    parser.parse_args()

    print("SIEM / Log Analyzer inicializado.")
    print(f"Diretório de logs brutos: {settings.raw_logs_dir}")
    print(f"Diretório de saída: {settings.output_dir}")
    print("Pipeline de análise ainda não implementado (próximas etapas).")

    return 0


if __name__ == "__main__":
    sys.exit(run())