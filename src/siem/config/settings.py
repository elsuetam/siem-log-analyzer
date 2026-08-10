"""Configurações centrais da aplicação, carregadas de variáveis de ambiente."""

from __future__ import annotations

from functools import lru_cache
from pathlib import Path

from pydantic import Field, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Configurações da aplicação carregadas do ambiente (.env).

    Todos os campos possuem valores padrão sensatos, permitindo que a
    aplicação rode "out of the box" sem exigir um arquivo .env em ambientes
    de desenvolvimento ou testes.
    """

    model_config = SettingsConfigDict(env_prefix="SIEM_", env_file=".env", extra="ignore")

    # --- Diretórios ---
    raw_logs_dir: Path = Field(
        default=Path("data/raw_logs"),
        description="Diretório onde os arquivos de log brutos são lidos.",
    )
    processed_dir: Path = Field(
        default=Path("data/processed"),
        description="Diretório onde dados já parseados/normalizados são armazenados.",
    )
    output_dir: Path = Field(
        default=Path("output"),
        description="Diretório raiz de saída (relatórios e dashboards).",
    )
    reports_dir: Path = Field(
        default=Path("output/reports"),
        description="Diretório onde relatórios gerados são salvos.",
    )
    dashboards_dir: Path = Field(
        default=Path("output/dashboards"),
        description="Diretório onde dashboards HTML gerados são salvos.",
    )

    # --- Comportamento geral ---
    log_level: str = Field(
        default="INFO",
        description="Nível de log da aplicação (DEBUG, INFO, WARNING, ERROR, CRITICAL).",
    )
    file_encoding: str = Field(
        default="utf-8",
        description="Encoding padrão usado para ler arquivos de log.",
    )
    timezone: str = Field(
        default="UTC",
        description="Timezone usada para normalizar timestamps dos logs.",
    )

    # --- Thresholds de detecção ---
    brute_force_attempts_threshold: int = Field(
        default=5,
        ge=1,
        description="Número de tentativas falhas de login para caracterizar brute force.",
    )
    brute_force_window_seconds: int = Field(
        default=60,
        ge=1,
        description="Janela de tempo (em segundos) para contabilizar tentativas de brute force.",
    )
    scanner_requests_threshold: int = Field(
        default=20,
        ge=1,
        description="Número de requisições distintas de um mesmo IP para caracterizar scanning.",
    )
    scanner_window_seconds: int = Field(
        default=10,
        ge=1,
        description="Janela de tempo (em segundos) para contabilizar comportamento de scanner.",
    )

    # --- Geração de incidentes ---
    incident_risk_score_threshold: float = Field(
        default=25.0,
        ge=0.0,
        le=100.0,
        description="Score de risco mínimo para que um IP gere um incidente formal.",
    )

    # --- Enriquecimento GeoIP ---
    enable_geoip: bool = Field(
        default=False,
        description="Se True, consulta a geolocalização dos IPs de origem via API externa.",
    )
    geoip_timeout_seconds: float = Field(
        default=5.0,
        ge=0.1,
        description="Tempo máximo de espera pela resposta da API de GeoIP.",
    )

    # --- Regras externas (Sigma / YARA) ---
    sigma_rules_dir: Path = Field(
        default=Path("rules/sigma"),
        description="Diretório contendo regras Sigma (.yml) a serem avaliadas.",
    )
    yara_rules_dir: Path = Field(
        default=Path("rules/yara"),
        description="Diretório contendo regras YARA (.yar/.yara) a serem avaliadas.",
    )

    # --- Persistência ---
    database_url: str = Field(
        default="sqlite:///./siem.db",
        description="String de conexão SQLAlchemy (SQLite por padrão; suporta Postgres etc.).",
    )

    # --- Detecção de anomalias via ML ---
    enable_ml_anomaly_detection: bool = Field(
        default=False,
        description="Se True, ativa o detector de anomalias baseado em Isolation Forest.",
    )
    ml_anomaly_contamination: float = Field(
        default=0.1,
        gt=0.0,
        le=0.5,
        description="Proporção esperada de IPs anômalos (hiperparâmetro do Isolation Forest).",
    )
    ml_anomaly_min_ips: int = Field(
        default=10,
        ge=1,
        description="Número mínimo de IPs distintos para rodar a detecção de anomalias.",
    )

    @field_validator("log_level")
    @classmethod
    def validate_log_level(cls, value: str) -> str:
        """Garante que o nível de log informado é válido."""
        valid_levels = {"DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"}
        normalized = value.upper()
        if normalized not in valid_levels:
            raise ValueError(
                f"log_level inválido: '{value}'. Deve ser um de {sorted(valid_levels)}."
            )
        return normalized

    def ensure_directories_exist(self) -> None:
        """Cria os diretórios de dados/saída caso ainda não existam.

        Deve ser chamado explicitamente na inicialização da aplicação (main.py),
        nunca automaticamente na leitura das configurações — para manter o
        carregamento de Settings livre de efeitos colaterais (importante para testes).
        """
        for directory in (
            self.raw_logs_dir,
            self.processed_dir,
            self.output_dir,
            self.reports_dir,
            self.dashboards_dir,
        ):
            directory.mkdir(parents=True, exist_ok=True)


@lru_cache
def get_settings() -> Settings:
    """Retorna a instância única (cacheada) das configurações da aplicação."""
    return Settings()