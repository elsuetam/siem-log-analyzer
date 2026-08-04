"""Utilitário genérico de agrupamento por janela deslizante temporal.

Usado por detectores que precisam identificar quando um número suficiente
de eventos relacionados ocorre dentro de um intervalo de tempo (ex: brute
force, scanning). A lógica é extraída aqui para evitar duplicação entre
detectores que compartilham esse mesmo padrão de análise.
"""

from __future__ import annotations

from collections.abc import Callable, Sequence
from datetime import datetime, timedelta
from typing import TypeVar

T = TypeVar("T")


def find_windows_meeting_threshold(
    items: Sequence[T],
    get_timestamp: Callable[[T], datetime],
    window: timedelta,
    meets_threshold: Callable[[Sequence[T]], bool],
) -> list[list[T]]:
    """Encontra janelas de tempo onde um grupo de itens atinge um critério.

    Os itens devem estar ordenados por timestamp antes de chamar esta função
    (não são ordenados internamente, para evitar custo de ordenação repetida
    quando o chamador já garante a ordem).

    Aplica uma janela deslizante com ponteiro duplo: para cada item (fim da
    janela), avança o início da janela até que todos os itens contidos
    estejam dentro do intervalo `window`. Sempre que o grupo resultante
    satisfaz `meets_threshold`, ele é registrado como uma janela válida, e o
    início da próxima busca avança para depois do fim da janela atual —
    evitando que a mesma sequência de eventos gere múltiplas detecções
    sobrepostas.

    Args:
        items: sequência de itens já ordenados por timestamp.
        get_timestamp: função que extrai o timestamp de um item.
        window: intervalo de tempo máximo entre o primeiro e o último item do grupo.
        meets_threshold: função que recebe o grupo atual (itens dentro da
            janela) e retorna True se esse grupo deve ser considerado uma detecção.

    Returns:
        Lista de grupos (cada um uma lista de itens) que atingiram o threshold,
        na ordem em que foram encontrados.
    """
    if not items:
        return []

    matched_groups: list[list[T]] = []
    window_start_idx = 0

    for end_idx in range(len(items)):
        while get_timestamp(items[end_idx]) - get_timestamp(items[window_start_idx]) > window:
            window_start_idx += 1

        current_group = list(items[window_start_idx : end_idx + 1])

        if meets_threshold(current_group):
            matched_groups.append(current_group)
            # Avança o início da janela para evitar sobreposição de detecções.
            window_start_idx = end_idx + 1

    return matched_groups