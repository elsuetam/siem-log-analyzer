"""Modelo de dados que representa a localização geográfica de um IP."""

from __future__ import annotations

from pydantic import BaseModel, Field


class GeoLocation(BaseModel):
    """Localização geográfica aproximada associada a um IP de origem."""

    country: str | None = Field(default=None, description="Nome do país.")
    country_code: str | None = Field(
        default=None, description="Código ISO do país (ex: BR, US)."
    )
    city: str | None = Field(default=None, description="Cidade aproximada.")
    latitude: float | None = Field(default=None, description="Latitude aproximada.")
    longitude: float | None = Field(default=None, description="Longitude aproximada.")
    isp: str | None = Field(default=None, description="Provedor de internet (ISP) do IP.")
    is_private: bool = Field(
        default=False,
        description="True se o IP é de rede privada/local (sem geolocalização pública).",
    )