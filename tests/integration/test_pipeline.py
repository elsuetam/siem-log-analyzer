"""Teste de integração do pipeline completo: arquivo de log -> incidentes."""

from __future__ import annotations

from pathlib import Path

from siem.detectors.brute_force import BruteForceDetector
from siem.detectors.scanner import ScannerDetector
from siem.parsers.combined_log_format import CombinedLogFormatParser
from siem.pipeline import run_pipeline

# 6 tentativas de login falhas do mesmo IP em ~5s -> deve disparar brute force
_BRUTE_FORCE_LINES = "\n".join(
    f'10.0.0.9 - - [10/Oct/2023:13:55:{i:02d} +0000] '
    f'"POST /login HTTP/1.1" 401 100 "-" "-"'
    for i in range(6)
)

# Uma requisição legítima que não deve gerar incidente
_NORMAL_LINE = (
    '127.0.0.1 - - [10/Oct/2023:14:00:00 +0000] '
    '"GET /index.html HTTP/1.1" 200 2326 "-" "Mozilla/5.0"'
)


def test_pipeline_end_to_end_generates_incident_for_brute_force(tmp_path: Path) -> None:
    """O pipeline completo deve gerar um incidente a partir de um arquivo de log real."""
    log_file = tmp_path / "access.log"
    log_file.write_text(f"{_BRUTE_FORCE_LINES}\n{_NORMAL_LINE}\n", encoding="utf-8")

    incidents = run_pipeline(
        log_files=[log_file],
        parser=CombinedLogFormatParser(),
        detectors=[
            BruteForceDetector(attempts_threshold=5, window_seconds=60),
            ScannerDetector(requests_threshold=20, window_seconds=10),
        ],
        risk_threshold=25.0,
    )

    assert len(incidents) == 1
    assert incidents[0].source_ip == "10.0.0.9"
    assert "brute_force_detector" in incidents[0].title


def test_pipeline_with_only_normal_traffic_generates_no_incidents(tmp_path: Path) -> None:
    """Tráfego normal, sem padrões suspeitos, não deve gerar incidentes."""
    log_file = tmp_path / "access.log"
    log_file.write_text(f"{_NORMAL_LINE}\n", encoding="utf-8")

    incidents = run_pipeline(
        log_files=[log_file],
        parser=CombinedLogFormatParser(),
        detectors=[
            BruteForceDetector(attempts_threshold=5, window_seconds=60),
            ScannerDetector(requests_threshold=20, window_seconds=10),
        ],
        risk_threshold=25.0,
    )

    assert incidents == []


def test_pipeline_skips_malformed_lines_without_failing(tmp_path: Path) -> None:
    """Linhas malformadas no arquivo não devem interromper o processamento das demais."""
    log_file = tmp_path / "access.log"
    log_file.write_text(f"linha totalmente inválida\n{_NORMAL_LINE}\n", encoding="utf-8")

    incidents = run_pipeline(
        log_files=[log_file],
        parser=CombinedLogFormatParser(),
        detectors=[BruteForceDetector(attempts_threshold=5, window_seconds=60)],
        risk_threshold=25.0,
    )

    # Não deve levantar exceção; e como não há padrão suspeito, nenhum incidente
    assert incidents == []


def test_pipeline_processes_multiple_files(tmp_path: Path) -> None:
    """O pipeline deve combinar entradas de múltiplos arquivos de log antes de detectar."""
    file_a = tmp_path / "a.log"
    file_b = tmp_path / "b.log"
    file_a.write_text("\n".join(_BRUTE_FORCE_LINES.split("\n")[:3]) + "\n", encoding="utf-8")
    file_b.write_text("\n".join(_BRUTE_FORCE_LINES.split("\n")[3:]) + "\n", encoding="utf-8")

    incidents = run_pipeline(
        log_files=[file_a, file_b],
        parser=CombinedLogFormatParser(),
        detectors=[BruteForceDetector(attempts_threshold=5, window_seconds=60)],
        risk_threshold=25.0,
    )

    # As 6 tentativas, mesmo separadas em 2 arquivos, devem ser combinadas e detectadas
    assert len(incidents) == 1
    assert incidents[0].source_ip == "10.0.0.9"