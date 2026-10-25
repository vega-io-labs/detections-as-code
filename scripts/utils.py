"""Small utility helpers shared across the sync engine."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import date, datetime, time, timezone
from pathlib import Path
from typing import Any, Callable, Generic, Iterable, Iterator, TypeVar

from .consts import SKILL_FILE_NAME

T = TypeVar("T")


def chunks(lst: list, n: int) -> Iterator[list]:
    for i in range(0, len(lst), n):
        yield lst[i : i + n]


def _files(directory: Path, *patterns: str) -> list[Path]:
    if not directory.is_dir():
        raise FileNotFoundError(f"directory not found: {directory}")
    return sorted({f for pattern in patterns for f in directory.glob(pattern)})


def yaml_files(directory: Path) -> list[Path]:
    return _files(directory, "**/*.yaml", "**/*.yml")


def skill_files(directory: Path) -> list[Path]:
    return _files(directory, f"**/{SKILL_FILE_NAME}")


@dataclass(frozen=True)
class UniqueKey(Generic[T]):
    what: str
    of: Callable[[T], str]
    why: str = ""


def duplicate_message(what: str, key: str, first: object, why: str = "") -> str:
    message = f"duplicate {what} {key!r} (also in {first})"
    return f"{message}. {why}" if why else message


def load_unique(
    files: Iterable[Path],
    parse: Callable[[Path], T | None],
    keys: Iterable[UniqueKey[T]],
) -> list[T]:
    keys = tuple(keys)
    first_file: dict[tuple[str, str], Path] = {}
    loaded: list[T] = []
    for f in files:
        item = parse(f)
        if item is None:
            continue
        for key in keys:
            value = key.of(item)
            first = first_file.setdefault((key.what, value), f)
            if first != f:
                raise ValueError(
                    f"{f}: {duplicate_message(key.what, value, first, key.why)}"
                )
        loaded.append(item)
    return loaded


def format_utc(value: datetime | None) -> str | None:
    if value is None:
        return None
    return value.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def parse_time(value: Any, where: str, key: str) -> datetime | None:
    if value is None:
        return None
    if isinstance(value, str) and value.strip():
        try:
            value = datetime.fromisoformat(value.strip())
        except ValueError:
            raise ValueError(
                f"{where}: '{key}' must be an ISO 8601 date or time, "
                f"e.g. '2027-01-31' or '2027-01-31T18:00:00Z' (got {value!r})"
            ) from None
    # PyYAML turns an unquoted 2027-01-01 into a date and an unquoted
    # timestamp into a datetime, so those reach this point already parsed.
    elif isinstance(value, date) and not isinstance(value, datetime):
        value = datetime.combine(value, time())
    if not isinstance(value, datetime):
        raise ValueError(
            f"{where}: '{key}' must be an ISO 8601 date or time (got {value!r})"
        )
    return value.replace(tzinfo=value.tzinfo or timezone.utc, microsecond=0)
