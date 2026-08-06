"""Enriquecimento de IPs com dados de geolocalização (GeoIP)."""

from __future__ import annotations

import ipaddress
import logging
from collections.abc import Callable
from typing import Any

import requests

from siem.models.geo_location import GeoLocation

logger = logging.getLogger(__name__)

_DEFAULT_API_URL = "http://ip-api.com/batch"
_BATCH_SIZE = 100  # limite da API gratuita do ip-api.com por requisição

HttpPost = Callable[..., "requests.Response"]


class GeoIPEnricher:
    """Enriquece IPs com dados de geolocalização usando a API pública do ip-api.com.

    A API gratuita não requer chave, mas tem limite de taxa (45 requisições/minuto)
    e não deve ser usada para volumes muito altos de IPs em produção — para esse
    cenário, considere migrar para uma base local (ex: MaxMind GeoLite2).
    """

    def __init__(
        self,
        timeout_seconds: float = 5.0,
        api_url: str = _DEFAULT_API_URL,
        http_post: HttpPost = requests.post,
    ) -> None:
        """Inicializa o enricher.

        Args:
            timeout_seconds: tempo máximo de espera pela resposta da API.
            api_url: URL do endpoint de batch lookup.
            http_post: função de transporte HTTP (injetável para testes).
        """
        self._timeout = timeout_seconds
        self._api_url = api_url
        self._http_post = http_post

    def enrich(self, ips: list[str]) -> dict[str, GeoLocation]:
        """Consulta a geolocalização de uma lista de IPs.

        IPs privados/reservados (ex: 127.0.0.1, 10.x.x.x, 192.168.x.x) são
        identificados localmente e não geram chamada de API — não têm
        geolocalização pública.

        Em caso de falha de rede ou resposta inesperada da API, retorna um
        dicionário vazio (ou parcial) e registra um warning — o enriquecimento
        é uma funcionalidade opcional e não deve interromper o pipeline.

        Args:
            ips: lista de IPs a serem consultados (pode conter duplicatas).

        Returns:
            Dicionário mapeando IP -> GeoLocation. IPs que falharam na consulta
            não aparecem no dicionário (o chamador deve tratar a ausência).
        """
        unique_ips = list(dict.fromkeys(ips))  # remove duplicatas preservando ordem
        results: dict[str, GeoLocation] = {}

        public_ips: list[str] = []
        for ip in unique_ips:
            if _is_private_ip(ip):
                results[ip] = GeoLocation(is_private=True)
            else:
                public_ips.append(ip)

        for batch_start in range(0, len(public_ips), _BATCH_SIZE):
            batch = public_ips[batch_start : batch_start + _BATCH_SIZE]
            results.update(self._query_batch(batch))

        return results

    def _query_batch(self, ips: list[str]) -> dict[str, GeoLocation]:
        payload = [{"query": ip} for ip in ips]

        try:
            response = self._http_post(self._api_url, json=payload, timeout=self._timeout)
            response.raise_for_status()
            data: list[dict[str, Any]] = response.json()
        except Exception as exc:  # noqa: BLE001 - enriquecimento é best-effort, nunca deve propagar
            logger.warning("Falha ao consultar GeoIP para %d IP(s): %s", len(ips), exc)
            return {}

        results: dict[str, GeoLocation] = {}
        for entry in data:
            ip = entry.get("query")
            if ip is None or entry.get("status") != "success":
                continue
            results[ip] = GeoLocation(
                country=entry.get("country"),
                country_code=entry.get("countryCode"),
                city=entry.get("city"),
                latitude=entry.get("lat"),
                longitude=entry.get("lon"),
                isp=entry.get("isp"),
            )

        return results


def _is_private_ip(ip: str) -> bool:
    """Determina se um IP é privado/reservado (sem geolocalização pública)."""
    try:
        parsed = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return parsed.is_private or parsed.is_loopback or parsed.is_reserved