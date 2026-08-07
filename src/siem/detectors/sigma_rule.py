"""Detector que avalia regras Sigma (YAML) contra entradas de log."""

from __future__ import annotations

import logging
from collections import defaultdict
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import yaml

from siem.detectors.base import BaseDetector
from siem.models.detection_event import DetectionEvent, DetectionSeverity
from siem.models.log_entry import LogEntry

logger = logging.getLogger(__name__)

_SEVERITY_MAP = {
    "low": DetectionSeverity.LOW,
    "medium": DetectionSeverity.MEDIUM,
    "high": DetectionSeverity.HIGH,
    "critical": DetectionSeverity.CRITICAL,
}

# Campos suportados na seleção de uma regra Sigma simplificada.
# Cada chave mapeia para uma função que extrai o valor correspondente de um LogEntry.
_FIELD_EXTRACTORS: dict[str, Any] = {
    "path": lambda e: e.path,
    "method": lambda e: e.method,
    "status_code": lambda e: e.status_code,
    "user_agent": lambda e: e.user_agent or "",
    "source_ip": lambda e: e.source_ip,
}


@dataclass
class SigmaRule:
    """Uma regra Sigma carregada e simplificada para avaliação."""

    rule_id: str
    title: str
    severity: DetectionSeverity
    selection: dict[str, Any]


class SigmaRuleDetector(BaseDetector):
    """Detector que carrega regras Sigma (.yml) de um diretório e as avalia.

    Suporta um subconjunto simplificado da especificação Sigma: uma única
    seção `selection` com condições de igualdade (`campo: valor`) ou
    substring (`campo_contains: valor`), combinadas com AND implícito.
    Não implementa a especificação Sigma completa (múltiplas seleções,
    OR/NOT explícitos, wildcards) — suficiente para regras de campo único
    comuns; extensível para funcionalidades futuras.
    """

    def __init__(self, rules_dir: Path) -> None:
        """Inicializa o detector carregando todas as regras do diretório.

        Args:
            rules_dir: diretório contendo arquivos .yml de regras Sigma.
                Se o diretório não existir ou estiver vazio, o detector
                simplesmente não gera detecções (comportamento seguro).
        """
        self._rules = self._load_rules(rules_dir)

    @property
    def name(self) -> str:
        return "sigma_rule_detector"

    def detect(self, entries: list[LogEntry]) -> list[DetectionEvent]:
        if not self._rules:
            return []

        events: list[DetectionEvent] = []
        for rule in self._rules:
            matches_by_ip: dict[str, list[LogEntry]] = defaultdict(list)
            for entry in entries:
                if self._matches_rule(entry, rule):
                    matches_by_ip[entry.source_ip].append(entry)

            for source_ip, matches in matches_by_ip.items():
                events.append(self._build_event(source_ip, matches, rule))

        return events

    def _matches_rule(self, entry: LogEntry, rule: SigmaRule) -> bool:
        for field, expected in rule.selection.items():
            if field.endswith("_contains"):
                base_field = field.removesuffix("_contains")
                extractor = _FIELD_EXTRACTORS.get(base_field)
                if extractor is None:
                    continue
                if str(expected).lower() not in str(extractor(entry)).lower():
                    return False
            else:
                extractor = _FIELD_EXTRACTORS.get(field)
                if extractor is None:
                    continue
                if extractor(entry) != expected:
                    return False
        return True

    def _build_event(
        self, source_ip: str, matches: list[LogEntry], rule: SigmaRule
    ) -> DetectionEvent:
        sorted_matches = sorted(matches, key=lambda e: e.timestamp)
        return DetectionEvent(
            detector_name=self.name,
            severity=rule.severity,
            source_ip=source_ip,
            description=f"Regra Sigma '{rule.title}' ({rule.rule_id}) disparada {len(matches)}x.",
            first_seen=sorted_matches[0].timestamp,
            last_seen=sorted_matches[-1].timestamp,
            occurrence_count=len(matches),
        )

    def _load_rules(self, rules_dir: Path) -> list[SigmaRule]:
        if not rules_dir.exists():
            logger.info("Diretório de regras Sigma não encontrado: %s", rules_dir)
            return []

        rules: list[SigmaRule] = []
        for rule_file in sorted(rules_dir.glob("*.yml")):
            try:
                raw = yaml.safe_load(rule_file.read_text(encoding="utf-8"))
                selection = raw["detection"]["selection"]
                rules.append(
                    SigmaRule(
                        rule_id=raw.get("id", rule_file.stem),
                        title=raw.get("title", rule_file.stem),
                        severity=_SEVERITY_MAP.get(
                            str(raw.get("severity", "medium")).lower(), DetectionSeverity.MEDIUM
                        ),
                        selection=selection,
                    )
                )
            except Exception:
                logger.warning("Falha ao carregar regra Sigma %s, ignorando.", rule_file.name)
                continue

        return rules