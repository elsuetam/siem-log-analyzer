"""Parser para o formato Combined Log Format (Apache/Nginx)."""

from __future__ import annotations

import re
from datetime import datetime

from siem.models.log_entry import LogEntry
from siem.parsers.base import BaseParser
from siem.parsers.exceptions import MalformedLogLineError

# Exemplo de linha no formato Combined Log Format:
# 127.0.0.1 - - [10/Oct/2023:13:55:36 +0000] "GET /index.html HTTP/1.1" 200 2326 "-" "Mozilla/5.0"
_COMBINED_LOG_PATTERN = re.compile(
    r'^(?P<ip>\S+) \S+ \S+ \[(?P<timestamp>[^\]]+)\] '
    r'"(?P<method>\S+) (?P<path>\S+) (?P<protocol>[^"]+)" '
    r'(?P<status>\d{3}) (?P<bytes>\S+) '
    r'"(?P<referer>[^"]*)" "(?P<user_agent>[^"]*)"$'
)

_TIMESTAMP_FORMAT = "%d/%b/%Y:%H:%M:%S %z"


class CombinedLogFormatParser(BaseParser):
    """Parser para logs de acesso web no formato Combined (Apache/Nginx).

    Referência do formato:
    https://httpd.apache.org/docs/2.4/logs.html#combined
    """

    def parse_line(self, line: str) -> LogEntry | None:
        """Interpreta uma linha no formato Combined Log Format.

        Args:
            line: linha bruta do log.

        Returns:
            LogEntry correspondente, ou None se a linha estiver vazia.

        Raises:
            MalformedLogLineError: se a linha não estiver vazia mas não
                corresponder ao formato Combined Log Format esperado.
        """
        stripped = line.strip()
        if not stripped:
            return None

        match = _COMBINED_LOG_PATTERN.match(stripped)
        if match is None:
            raise MalformedLogLineError(
                line=stripped,
                reason="não corresponde ao padrão Combined Log Format",
            )

        groups = match.groupdict()

        try:
            timestamp = datetime.strptime(groups["timestamp"], _TIMESTAMP_FORMAT)
        except ValueError as exc:
            raise MalformedLogLineError(
                line=stripped,
                reason=f"timestamp inválido: {groups['timestamp']!r}",
            ) from exc

        try:
            bytes_sent = 0 if groups["bytes"] == "-" else int(groups["bytes"])
        except ValueError as exc:
            raise MalformedLogLineError(
                line=stripped,
                reason=f"campo bytes inválido: {groups['bytes']!r}",
            ) from exc

        try:
            return LogEntry(
                timestamp=timestamp,
                source_ip=groups["ip"],
                method=groups["method"],
                path=groups["path"],
                protocol=groups["protocol"],
                status_code=int(groups["status"]),
                bytes_sent=bytes_sent,
                referer=groups["referer"],
                user_agent=groups["user_agent"],
                raw_line=stripped,
            )
        except ValueError as exc:
            raise MalformedLogLineError(
                line=stripped,
                reason=f"validação do LogEntry falhou: {exc}",
            ) from exc