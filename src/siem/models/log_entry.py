"""Modelo de dados que representa uma entrada de log normalizada."""

from __future__ import annotations

from datetime import datetime

from pydantic import BaseModel, Field, field_validator


class LogEntry(BaseModel):
    """Representa uma única linha de log de acesso web, já normalizada.

    Os campos aqui foram escolhidos para viabilizar os detectores das próximas
    etapas: brute force e scanners dependem de `source_ip` + `timestamp`;
    SQL Injection e Directory Traversal dependem de `path`; User Agents
    suspeitos dependem de `user_agent`.
    """

    timestamp: datetime = Field(description="Data e hora do evento registrado no log.")
    source_ip: str = Field(description="Endereço IP de origem da requisição.")
    method: str = Field(description="Método HTTP da requisição (GET, POST, etc.).")
    path: str = Field(description="Caminho/URL solicitado.")
    protocol: str = Field(description="Versão do protocolo HTTP (ex: HTTP/1.1).")
    status_code: int = Field(ge=100, le=599, description="Código de status HTTP da resposta.")
    bytes_sent: int = Field(ge=0, description="Quantidade de bytes enviados na resposta.")
    referer: str | None = Field(default=None, description="Cabeçalho Referer, se presente.")
    user_agent: str | None = Field(default=None, description="Cabeçalho User-Agent, se presente.")
    raw_line: str = Field(description="Linha original do log, preservada para auditoria.")

    @field_validator("method")
    @classmethod
    def normalize_method(cls, value: str) -> str:
        """Normaliza o método HTTP para maiúsculas."""
        return value.upper()

    @field_validator("referer", "user_agent")
    @classmethod
    def blank_dash_to_none(cls, value: str | None) -> str | None:
        """Converte o valor convencional '-' (campo ausente em logs) para None."""
        if value is None or value == "-":
            return None
        return value