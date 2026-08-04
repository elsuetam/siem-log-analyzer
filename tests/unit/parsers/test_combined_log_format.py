"""Testes unitários para CombinedLogFormatParser."""

from __future__ import annotations

import pytest

from siem.parsers.combined_log_format import CombinedLogFormatParser
from siem.parsers.exceptions import MalformedLogLineError

VALID_LINE = (
    '127.0.0.1 - - [10/Oct/2023:13:55:36 +0000] '
    '"GET /index.html HTTP/1.1" 200 2326 '
    '"http://example.com/" "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"'
)

LINE_WITHOUT_REFERER_OR_USER_AGENT = (
    '10.0.0.5 - - [11/Oct/2023:08:12:01 +0000] '
    '"POST /login HTTP/1.1" 401 512 "-" "-"'
)


@pytest.fixture
def parser() -> CombinedLogFormatParser:
    return CombinedLogFormatParser()


def test_parse_valid_line(parser: CombinedLogFormatParser) -> None:
    """Uma linha válida deve gerar um LogEntry com todos os campos corretos."""
    entry = parser.parse_line(VALID_LINE)

    assert entry is not None
    assert entry.source_ip == "127.0.0.1"
    assert entry.method == "GET"
    assert entry.path == "/index.html"
    assert entry.protocol == "HTTP/1.1"
    assert entry.status_code == 200
    assert entry.bytes_sent == 2326
    assert entry.referer == "http://example.com/"
    assert entry.user_agent == "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"


def test_parse_line_normalizes_dash_to_none(parser: CombinedLogFormatParser) -> None:
    """Campos '-' (referer/user_agent ausentes) devem virar None."""
    entry = parser.parse_line(LINE_WITHOUT_REFERER_OR_USER_AGENT)

    assert entry is not None
    assert entry.referer is None
    assert entry.user_agent is None
    assert entry.method == "POST"
    assert entry.status_code == 401


def test_parse_empty_line_returns_none(parser: CombinedLogFormatParser) -> None:
    """Linhas vazias ou só com espaços devem ser ignoradas (retornar None)."""
    assert parser.parse_line("") is None
    assert parser.parse_line("   \n") is None


def test_parse_malformed_line_raises_error(parser: CombinedLogFormatParser) -> None:
    """Uma linha que não corresponde ao formato deve levantar MalformedLogLineError."""
    with pytest.raises(MalformedLogLineError):
        parser.parse_line("isso não é um log válido de forma alguma")


def test_parse_line_with_invalid_timestamp_raises_error(
    parser: CombinedLogFormatParser,
) -> None:
    """Uma linha com timestamp em formato inválido deve levantar erro claro."""
    bad_line = VALID_LINE.replace("10/Oct/2023:13:55:36 +0000", "data-invalida")

    with pytest.raises(MalformedLogLineError):
        parser.parse_line(bad_line)


def test_parse_lines_skips_blank_and_collects_valid(
    parser: CombinedLogFormatParser,
) -> None:
    """parse_lines deve ignorar linhas em branco e retornar apenas entradas válidas."""
    lines = [VALID_LINE, "", "   ", LINE_WITHOUT_REFERER_OR_USER_AGENT]

    entries = parser.parse_lines(lines)

    assert len(entries) == 2
    assert entries[0].source_ip == "127.0.0.1"
    assert entries[1].source_ip == "10.0.0.5"


def test_parse_lines_propagates_malformed_line_error(
    parser: CombinedLogFormatParser,
) -> None:
    """parse_lines deve propagar a exceção se qualquer linha for malformada."""
    lines = [VALID_LINE, "linha totalmente inválida"]

    with pytest.raises(MalformedLogLineError):
        parser.parse_lines(lines)

def test_parse_line_with_invalid_bytes_field_raises_error(
    parser: CombinedLogFormatParser,
) -> None:
    """Uma linha com campo bytes não-numérico (e diferente de '-') deve levantar erro."""
    bad_line = VALID_LINE.replace(" 2326 ", " abc ")

    with pytest.raises(MalformedLogLineError):
        parser.parse_line(bad_line)


def test_parse_line_with_out_of_range_status_code_raises_error(
    parser: CombinedLogFormatParser,
) -> None:
    """Um status code de 3 dígitos mas fora do range HTTP válido deve ser rejeitado."""
    bad_line = VALID_LINE.replace(
        '"GET /index.html HTTP/1.1" 200', '"GET /index.html HTTP/1.1" 999'
    )

    with pytest.raises(MalformedLogLineError):
        parser.parse_line(bad_line)