"""Testes unitários para GeoIPEnricher."""

from __future__ import annotations

from typing import Any
from unittest.mock import MagicMock

import pytest

from siem.enrichment.geoip import GeoIPEnricher, _is_private_ip


def _fake_response(json_data: Any, status_ok: bool = True) -> MagicMock:
    response = MagicMock()
    response.json.return_value = json_data
    if status_ok:
        response.raise_for_status.return_value = None
    else:
        response.raise_for_status.side_effect = Exception("HTTP error")
    return response


@pytest.mark.parametrize(
    ("ip", "expected"),
    [
        ("127.0.0.1", True),
        ("192.168.1.1", True),
        ("10.0.0.5", True),
        ("172.16.0.1", True),
        ("8.8.8.8", False),
        ("1.1.1.1", False),
        ("nao-e-um-ip", False),
    ],
)
def test_is_private_ip(ip: str, expected: bool) -> None:
    """Deve identificar corretamente IPs privados/reservados vs. públicos."""
    assert _is_private_ip(ip) is expected


def test_enrich_skips_api_call_for_private_ips_only() -> None:
    """Se todos os IPs são privados, nenhuma chamada HTTP deve ser feita."""
    http_post = MagicMock()
    enricher = GeoIPEnricher(http_post=http_post)

    results = enricher.enrich(["127.0.0.1", "192.168.0.1"])

    http_post.assert_not_called()
    assert results["127.0.0.1"].is_private is True
    assert results["192.168.0.1"].is_private is True


def test_enrich_calls_api_for_public_ips() -> None:
    """IPs públicos devem gerar uma chamada à API com os dados corretos."""
    http_post = MagicMock(
        return_value=_fake_response(
            [
                {
                    "query": "8.8.8.8",
                    "status": "success",
                    "country": "United States",
                    "countryCode": "US",
                    "city": "Mountain View",
                    "lat": 37.4,
                    "lon": -122.1,
                    "isp": "Google LLC",
                }
            ]
        )
    )
    enricher = GeoIPEnricher(http_post=http_post)

    results = enricher.enrich(["8.8.8.8"])

    http_post.assert_called_once()
    assert results["8.8.8.8"].country == "United States"
    assert results["8.8.8.8"].city == "Mountain View"
    assert results["8.8.8.8"].is_private is False


def test_enrich_skips_entries_with_failed_status() -> None:
    """Entradas com status diferente de 'success' na resposta não devem virar resultado."""
    http_post = MagicMock(
        return_value=_fake_response([{"query": "9.9.9.9", "status": "fail"}])
    )
    enricher = GeoIPEnricher(http_post=http_post)

    results = enricher.enrich(["9.9.9.9"])

    assert "9.9.9.9" not in results


def test_enrich_returns_empty_on_network_failure() -> None:
    """Falha de rede/timeout não deve propagar exceção, apenas retornar vazio."""
    http_post = MagicMock(side_effect=ConnectionError("network down"))
    enricher = GeoIPEnricher(http_post=http_post)

    results = enricher.enrich(["8.8.8.8"])

    assert results == {}


def test_enrich_returns_empty_on_http_error_status() -> None:
    """Resposta HTTP com status de erro não deve propagar exceção."""
    http_post = MagicMock(return_value=_fake_response([], status_ok=False))
    enricher = GeoIPEnricher(http_post=http_post)

    results = enricher.enrich(["8.8.8.8"])

    assert results == {}


def test_enrich_deduplicates_repeated_ips() -> None:
    """IPs repetidos na entrada devem gerar apenas uma consulta por IP único."""
    http_post = MagicMock(
        return_value=_fake_response(
            [{"query": "8.8.8.8", "status": "success", "country": "United States"}]
        )
    )
    enricher = GeoIPEnricher(http_post=http_post)

    enricher.enrich(["8.8.8.8", "8.8.8.8", "8.8.8.8"])

    call_payload = http_post.call_args.kwargs["json"]
    assert call_payload == [{"query": "8.8.8.8"}]


def test_enrich_splits_into_batches_of_100() -> None:
    """Mais de 100 IPs públicos deve gerar múltiplas chamadas em lote."""
    http_post = MagicMock(return_value=_fake_response([]))
    enricher = GeoIPEnricher(http_post=http_post)
    many_ips = [f"8.8.{i // 256}.{i % 256}" for i in range(150)]

    enricher.enrich(many_ips)

    assert http_post.call_count == 2