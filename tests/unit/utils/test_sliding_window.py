"""Testes unitários para find_windows_meeting_threshold."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

from siem.utils.sliding_window import find_windows_meeting_threshold

BASE_TIME = datetime(2024, 1, 1, 12, 0, 0, tzinfo=UTC)


def _at(offset_seconds: float) -> datetime:
    return BASE_TIME + timedelta(seconds=offset_seconds)


def test_empty_items_returns_no_windows() -> None:
    """Uma sequência vazia não deve produzir nenhuma janela."""
    result = find_windows_meeting_threshold(
        items=[],
        get_timestamp=lambda x: x,
        window=timedelta(seconds=10),
        meets_threshold=lambda group: len(group) >= 1,
    )

    assert result == []


def test_single_group_within_window_meeting_threshold() -> None:
    """Itens dentro da janela que atingem o threshold devem formar um grupo."""
    timestamps = [_at(0), _at(2), _at(4)]

    result = find_windows_meeting_threshold(
        items=timestamps,
        get_timestamp=lambda ts: ts,
        window=timedelta(seconds=10),
        meets_threshold=lambda group: len(group) >= 3,
    )

    assert len(result) == 1
    assert result[0] == timestamps


def test_no_group_when_threshold_never_met() -> None:
    """Se nenhum grupo atinge o threshold, nenhuma janela deve ser retornada."""
    timestamps = [_at(0), _at(2)]

    result = find_windows_meeting_threshold(
        items=timestamps,
        get_timestamp=lambda ts: ts,
        window=timedelta(seconds=10),
        meets_threshold=lambda group: len(group) >= 5,
    )

    assert result == []


def test_items_outside_window_are_excluded_from_group() -> None:
    """Itens fora da janela de tempo não devem ser agrupados junto com os demais."""
    timestamps = [_at(0), _at(1), _at(100)]

    result = find_windows_meeting_threshold(
        items=timestamps,
        get_timestamp=lambda ts: ts,
        window=timedelta(seconds=10),
        meets_threshold=lambda group: len(group) >= 2,
    )

    # Apenas os dois primeiros formam um grupo válido; o terceiro está isolado
    assert len(result) == 1
    assert result[0] == [_at(0), _at(1)]


def test_window_advances_past_matched_group_avoiding_overlap() -> None:
    """Após uma detecção, a próxima busca não deve reutilizar os mesmos itens."""
    timestamps = [_at(0), _at(1), _at(2), _at(3), _at(4), _at(5)]

    result = find_windows_meeting_threshold(
        items=timestamps,
        get_timestamp=lambda ts: ts,
        window=timedelta(seconds=10),
        meets_threshold=lambda group: len(group) >= 3,
    )

    # Threshold de 3 é atingido no 3º item; a partir daí a janela reinicia
    assert len(result) == 2
    assert result[0] == [_at(0), _at(1), _at(2)]
    assert result[1] == [_at(3), _at(4), _at(5)]


def test_custom_threshold_function_based_on_distinct_values() -> None:
    """meets_threshold pode avaliar qualquer critério sobre o grupo, não só contagem."""
    entries = [("a", _at(0)), ("a", _at(1)), ("b", _at(2)), ("c", _at(3))]

    result = find_windows_meeting_threshold(
        items=entries,
        get_timestamp=lambda e: e[1],
        window=timedelta(seconds=10),
        meets_threshold=lambda group: len({v for v, _ in group}) >= 3,
    )

    assert len(result) == 1
    assert len(result[0]) == 4