"""Renderização do dashboard HTML a partir dos resultados do pipeline."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path

from jinja2 import Environment, FileSystemLoader, select_autoescape

from siem.models.incident import Incident

_TEMPLATES_DIR = Path(__file__).resolve().parents[3] / "templates"


@dataclass
class _IncidentView:
    """Wrapper de exibição sobre Incident, adicionando dados derivados para o template."""

    incident: Incident

    @property
    def highest_severity(self) -> str:
        """Retorna a severidade mais alta entre os eventos contribuintes (borda colorida)."""
        contributing = self.incident.risk_details.contributing_events
        severities = [event.severity.value for event in contributing]
        order = ["critical", "high", "medium", "low"]
        for level in order:
            if level in severities:
                return level
        return "low"

    def __getattr__(self, item: str) -> object:
        # Delega qualquer atributo não definido aqui para o Incident original,
        # permitindo que o template acesse incident.title, incident.source_ip, etc.
        return getattr(self.incident, item)


@dataclass
class DashboardData:
    """Dados agregados necessários para renderizar o dashboard."""

    incidents: list[Incident]
    total_entries: int = 0
    total_detections: int = 0


class DashboardRenderer:
    """Renderiza o dashboard HTML a partir dos dados de uma execução do pipeline."""

    def __init__(self, templates_dir: Path = _TEMPLATES_DIR) -> None:
        self._env = Environment(
            loader=FileSystemLoader(str(templates_dir)),
            autoescape=select_autoescape(["html", "j2"]),
        )

    def render(self, data: DashboardData) -> str:
        """Gera o HTML do dashboard como string.

        Args:
            data: dados agregados da execução (incidentes, contadores).

        Returns:
            Conteúdo HTML completo, pronto para ser salvo em arquivo.
        """
        template = self._env.get_template("dashboard.html.j2")
        return template.render(
            incidents=[_IncidentView(incident) for incident in data.incidents],
            total_entries=data.total_entries,
            total_detections=data.total_detections,
            generated_at=datetime.now(UTC).strftime("%Y-%m-%d %H:%M:%S UTC"),
        )

    def render_to_file(self, data: DashboardData, output_path: Path) -> Path:
        """Gera o dashboard e salva em um arquivo HTML.

        Args:
            data: dados agregados da execução.
            output_path: caminho do arquivo .html a ser criado (diretórios pais
                são criados automaticamente se não existirem).

        Returns:
            O mesmo output_path recebido, para conveniência de encadeamento.
        """
        html = self.render(data)
        output_path.parent.mkdir(parents=True, exist_ok=True)
        output_path.write_text(html, encoding="utf-8")
        return output_path