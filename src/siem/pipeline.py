"""Orquestração do pipeline completo de análise de logs.

Fluxo: leitura de arquivo(s) de log -> parsing -> detecção -> score de
risco -> geração de incidentes. Ver docs/architecture.md para o diagrama
completo do pipeline.
"""

from __future__ import annotations

import logging
from pathlib import Path

from siem.analysis.risk_score import calculate_risk_scores
from siem.detectors.base import BaseDetector
from siem.incidents.generator import generate_incidents
from siem.models.detection_event import DetectionEvent
from siem.models.incident import Incident
from siem.models.log_entry import LogEntry
from siem.parsers.base import BaseParser
from siem.parsers.exceptions import MalformedLogLineError

logger = logging.getLogger(__name__)


def parse_log_file(log_file: Path, parser: BaseParser, encoding: str) -> list[LogEntry]:
    """Lê e interpreta um arquivo de log, pulando linhas malformadas.

    Linhas malformadas são registradas como warning e ignoradas — um único
    log de acesso web em produção pode ter linhas corrompidas ou de formatos
    inesperados, e isso não deve interromper a análise do restante do arquivo.

    Args:
        log_file: caminho do arquivo de log a ser lido.
        parser: implementação de BaseParser a ser usada.
        encoding: encoding do arquivo (ex: 'utf-8').

    Returns:
        Lista de LogEntry parseadas com sucesso.
    """
    lines = log_file.read_text(encoding=encoding).splitlines()

    entries: list[LogEntry] = []
    for line_number, line in enumerate(lines, start=1):
        try:
            entry = parser.parse_line(line)
        except MalformedLogLineError as exc:
            logger.warning(
                "Linha %d de %s ignorada (%s)", line_number, log_file.name, exc.reason
            )
            continue

        if entry is not None:
            entries.append(entry)

    return entries


def run_pipeline(
    log_files: list[Path],
    parser: BaseParser,
    detectors: list[BaseDetector],
    risk_threshold: float,
    encoding: str = "utf-8",
) -> list[Incident]:
    """Executa o pipeline completo de análise sobre um conjunto de arquivos de log.

    Args:
        log_files: lista de arquivos de log a serem processados.
        parser: parser a ser usado para interpretar as linhas.
        detectors: lista de detectores a serem executados sobre as entradas parseadas.
        risk_threshold: score mínimo (0-100) para geração de incidente.
        encoding: encoding usado para ler os arquivos.

    Returns:
        Lista de Incident gerados, ordenada do maior para o menor score de risco.
    """
    all_entries: list[LogEntry] = []
    for log_file in log_files:
        entries = parse_log_file(log_file, parser, encoding)
        logger.info("%s: %d entradas parseadas", log_file.name, len(entries))
        all_entries.extend(entries)

    all_detections: list[DetectionEvent] = []
    for detector in detectors:
        detections = detector.detect(all_entries)
        logger.info("%s: %d detecções", detector.name, len(detections))
        all_detections.extend(detections)

    risk_scores = calculate_risk_scores(all_detections)
    incidents = generate_incidents(risk_scores, threshold=risk_threshold)

    logger.info(
        "Pipeline concluído: %d entradas, %d detecções, %d incidentes gerados",
        len(all_entries),
        len(all_detections),
        len(incidents),
    )

    return incidents