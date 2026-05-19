"""Small utility helpers shared across the sync engine."""

from __future__ import annotations

from typing import Iterator


def chunks(lst: list, n: int) -> Iterator[list]:
    for i in range(0, len(lst), n):
        yield lst[i : i + n]
