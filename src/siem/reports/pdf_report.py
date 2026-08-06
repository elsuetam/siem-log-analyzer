"""Geração de relatórios em PDF a partir dos resultados do pipeline."""

from __future__ import annotations

from collections import Counter
from datetime import UTC, datetime
from pathlib import Path

from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import cm
from reportlab.platypus import (
    Paragraph,
    SimpleDocTemplate,
    Spacer,
    Table,
    TableStyle,
)

from siem.models.incident import Incident

_SEVERITY_ORDER = ["critical", "high", "medium", "low"]
_SEVERITY_COLORS = {
    "critical": colors.HexColor("#e5484d"),
    "high": colors.HexColor("#f5a623"),
    "medium": colors.HexColor("#f7d154"),
    "low": colors.HexColor("#5eb1ef"),
}


class PDFReportGenerator:
    """Gera um relatório em PDF resumindo os incidentes de uma execução do pipeline."""

    def __init__(self) -> None:
        self._styles = getSampleStyleSheet()
        self._title_style = ParagraphStyle(
            "ReportTitle", parent=self._styles["Title"], fontSize=20, spaceAfter=4
        )
        self._subtitle_style = ParagraphStyle(
            "ReportSubtitle",
            parent=self._styles["Normal"],
            textColor=colors.grey,
            spaceAfter=20,
        )
        self._section_style = ParagraphStyle(
            "SectionHeader", parent=self._styles["Heading2"], spaceBefore=16, spaceAfter=8
        )

    def generate(
        self,
        incidents: list[Incident],
        output_path: Path,
        total_entries: int,
        total_detections: int,
    ) -> Path:
        """Gera o relatório em PDF e salva no caminho informado.

        Args:
            incidents: lista de incidentes a incluir no relatório.
            output_path: caminho do arquivo .pdf a ser criado (diretórios pais
                são criados automaticamente se não existirem).
            total_entries: total de entradas de log analisadas.
            total_detections: total de detecções brutas geradas pelos detectores.

        Returns:
            O mesmo output_path recebido, para conveniência de encadeamento.
        """
        output_path.parent.mkdir(parents=True, exist_ok=True)

        doc = SimpleDocTemplate(
            str(output_path),
            pagesize=A4,
            topMargin=2 * cm,
            bottomMargin=2 * cm,
            leftMargin=2 * cm,
            rightMargin=2 * cm,
        )

        story = [
            Paragraph("SIEM / Log Analyzer — Relatório de Incidentes", self._title_style),
            Paragraph(
                f"Gerado em {datetime.now(UTC).strftime('%Y-%m-%d %H:%M:%S UTC')}",
                self._subtitle_style,
            ),
            *self._build_summary_section(incidents, total_entries, total_detections),
            *self._build_severity_section(incidents),
            *self._build_incidents_section(incidents),
        ]

        doc.build(story)
        return output_path

    def _build_summary_section(
        self, incidents: list[Incident], total_entries: int, total_detections: int
    ) -> list[object]:
        data = [
            ["Métrica", "Valor"],
            ["Incidentes gerados", str(len(incidents))],
            ["Entradas de log analisadas", str(total_entries)],
            ["Detecções brutas", str(total_detections)],
        ]
        table = Table(data, colWidths=[10 * cm, 6 * cm])
        table.setStyle(self._default_table_style())
        return [Paragraph("Resumo Executivo", self._section_style), table]

    def _build_severity_section(self, incidents: list[Incident]) -> list[object]:
        if not incidents:
            return [
                Paragraph("Distribuição por Severidade", self._section_style),
                Paragraph("Nenhum incidente registrado.", self._styles["Normal"]),
            ]

        counts = Counter(self._highest_severity(incident) for incident in incidents)
        data = [["Severidade", "Ocorrências"]]
        data.extend(
            [severity.upper(), str(counts[severity])]
            for severity in _SEVERITY_ORDER
            if counts[severity] > 0
        )

        table = Table(data, colWidths=[10 * cm, 6 * cm])
        table.setStyle(self._default_table_style())
        return [Paragraph("Distribuição por Severidade", self._section_style), table]

    def _build_incidents_section(self, incidents: list[Incident]) -> list[object]:
        elements: list[object] = [Paragraph("Detalhamento dos Incidentes", self._section_style)]

        if not incidents:
            elements.append(Paragraph("Nenhum incidente identificado.", self._styles["Normal"]))
            return elements

        sorted_incidents = sorted(incidents, key=lambda i: i.risk_score, reverse=True)
        for incident in sorted_incidents:
            elements.append(Spacer(1, 8))
            elements.append(
                Paragraph(
                    f"<b>{incident.title}</b>",
                    ParagraphStyle("IncidentTitle", parent=self._styles["Normal"], fontSize=11),
                )
            )
            elements.append(
                Paragraph(
                    f"IP: {incident.source_ip} | Score: {incident.risk_score:.0f} | "
                    f"Status: {incident.status.value} | "
                    f"Eventos: {len(incident.risk_details.contributing_events)}",
                    ParagraphStyle(
                        "IncidentMeta",
                        parent=self._styles["Normal"],
                        textColor=colors.grey,
                        fontSize=9,
                    ),
                )
            )

        return elements

    def _default_table_style(self) -> TableStyle:
        return TableStyle(
            [
                ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#1a2028")),
                ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
                ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
                ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#cccccc")),
                ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#f5f5f5")]),
                ("TOPPADDING", (0, 0), (-1, -1), 6),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
                ("LEFTPADDING", (0, 0), (-1, -1), 8),
            ]
        )

    def _highest_severity(self, incident: Incident) -> str:
        contributing = incident.risk_details.contributing_events
        severities = [event.severity.value for event in contributing]
        for level in _SEVERITY_ORDER:
            if level in severities:
                return level
        return "low"