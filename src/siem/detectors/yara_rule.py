"""Detector que avalia regras YARA contra o texto bruto das entradas de log."""

from __future__ import annotations

import logging
from collections import defaultdict
from pathlib import Path

from siem.detectors.base import BaseDetector
from siem.models.detection_event import DetectionEvent, DetectionSeverity
from siem.models.log_entry import LogEntry

logger = logging.getLogger(__name__)

try:
    import yara

    _YARA_AVAILABLE = True
except ImportError:  # pragma: no cover - depende de dependência opcional do sistema
    _YARA_AVAILABLE = False


class YaraDetector(BaseDetector):
    """Detector que escaneia a linha bruta de cada log contra regras YARA.

    Se a biblioteca yara-python não estiver instalada, ou o diretório de
    regras não existir/estiver vazio, o detector não gera detecções — a
    ausência de YARA nunca interrompe o restante do pipeline.
    """

    def __init__(self, rules_dir: Path) -> None:
        """Inicializa o detector compilando as regras do diretório.

        Args:
            rules_dir: diretório contendo arquivos .yar/.yara.
        """
        self._compiled_rules = self._compile_rules(rules_dir) if _YARA_AVAILABLE else None

    @property
    def name(self) -> str:
        return "yara_detector"

    def detect(self, entries: list[LogEntry]) -> list[DetectionEvent]:
        if self._compiled_rules is None:
            return []

        matches_by_ip: dict[str, list[LogEntry]] = defaultdict(list)
        for entry in entries:
            if self._compiled_rules.match(data=entry.raw_line):
                matches_by_ip[entry.source_ip].append(entry)

        return [self._build_event(ip, matches) for ip, matches in matches_by_ip.items()]

    def _build_event(self, source_ip: str, matches: list[LogEntry]) -> DetectionEvent:
        sorted_matches = sorted(matches, key=lambda e: e.timestamp)
        return DetectionEvent(
            detector_name=self.name,
            severity=DetectionSeverity.MEDIUM,
            source_ip=source_ip,
            description=(
                f"{len(matches)} requisição(ões) do IP {source_ip} "
                "corresponderam a regra(s) YARA (assinatura conhecida)."
            ),
            first_seen=sorted_matches[0].timestamp,
            last_seen=sorted_matches[-1].timestamp,
            occurrence_count=len(matches),
        )

    def _compile_rules(self, rules_dir: Path) -> yara.Rules | None:  # noqa: F821
        if not rules_dir.exists():
            logger.info("Diretório de regras YARA não encontrado: %s", rules_dir)
            return None

        rule_files = {f.stem: str(f) for f in rules_dir.glob("*.yar")}
        rule_files.update({f.stem: str(f) for f in rules_dir.glob("*.yara")})

        if not rule_files:
            return None

        try:
            return yara.compile(filepaths=rule_files)
        except Exception:
            logger.warning("Falha ao compilar regras YARA em %s, ignorando.", rules_dir)
            return None