"""Small utility helpers shared across the sync engine."""

from __future__ import annotations

from pathlib import Path
from typing import Iterator


def chunks(lst: list, n: int) -> Iterator[list]:
    for i in range(0, len(lst), n):
        yield lst[i : i + n]


def yaml_files(directory: Path) -> list[Path]:
    if not directory.is_dir():
        raise FileNotFoundError(f"directory not found: {directory}")
    return sorted([*directory.glob("**/*.yaml"), *directory.glob("**/*.yml")])
