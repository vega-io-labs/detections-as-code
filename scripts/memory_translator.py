"""Translate the memory YAML schema to Vega API payloads.

Mapping:
  title       -> title (also the identity the sync matches on)
  description -> description
  content     -> content
  status      -> MemoryStatus enum value (enabled|disabled, defaults to enabled)
  expiresAt   -> expiresAt, ISO 8601 in UTC
  entities    -> entities, type upper-cased (account|device|ip|domain)
  labels      -> labelIds, resolved by name at sync time, plus the managed label

Validation mirrors the server's own rules (see consts.py) so a bad value fails
the PR check rather than the post-merge sync.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import date, datetime, timezone
from typing import Any

from .consts import (
    DEFAULT_MEMORY_STATUS,
    MANAGED_MEMORY_LABEL,
    MEMORY_CONTENT_MAX_LEN,
    MEMORY_DESCRIPTION_MAX_LEN,
    MEMORY_ENTITIES_MAX,
    MEMORY_ENTITY_VALUE_MAX_LEN,
    MEMORY_MANDATORY_FIELDS,
    MEMORY_TITLE_MAX_LEN,
    VALID_MEMORY_ENTITY_TYPES,
    VALID_MEMORY_STATUSES,
    MemoryStatus,
)

_ALLOWED_FIELDS: frozenset[str] = frozenset(
    {*MEMORY_MANDATORY_FIELDS, "status", "expiresAt", "entities", "labels"}
)

# A misspelt key is silently ignored by a YAML loader, and for these the
# result is the opposite of what the author meant: `enabled: false` would
# leave the memory on.
_FIELD_HINTS: dict[str, str] = {
    "enabled": "use 'status: enabled' or 'status: disabled'",
    "state": "memories use 'status', not 'state'",
    "name": "memories use 'title', not 'name'",
    "labelIds": "list label names under 'labels'; the sync resolves the IDs",
    "id": (
        "memories have no 'id': the title is what links a file to its "
        "memory in Vega"
    ),
}


@dataclass(frozen=True)
class MemorySpec:
    title: str
    description: str
    content: str
    status: MemoryStatus
    expires_at: datetime | None
    entities: tuple[tuple[str, str], ...]
    labels: tuple[str, ...] = field(default_factory=tuple)

    @property
    def expires_at_iso(self) -> str | None:
        return format_time(self.expires_at)


def format_time(value: datetime | None) -> str | None:
    if value is None:
        return None
    return value.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def parse_time(value: Any, where: str) -> datetime | None:
    if value is None:
        return None
    # PyYAML turns an unquoted 2027-01-01 into a date and an unquoted
    # timestamp into a datetime, so all three shapes reach this point.
    if isinstance(value, datetime):
        parsed = value
    elif isinstance(value, date):
        parsed = datetime(value.year, value.month, value.day)
    elif isinstance(value, str) and value.strip():
        try:
            parsed = datetime.fromisoformat(value.strip())
        except ValueError:
            raise ValueError(
                f"{where}: 'expiresAt' must be an ISO 8601 date or time, "
                f"e.g. '2027-01-31' or '2027-01-31T18:00:00Z' (got {value!r})"
            ) from None
    else:
        raise ValueError(
            f"{where}: 'expiresAt' must be an ISO 8601 date or time "
            f"(got {value!r})"
        )
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.replace(microsecond=0)


def _text(doc: dict[str, Any], key: str, max_len: int, where: str) -> str:
    value = doc.get(key)
    if value is None:
        raise ValueError(f"{where}: missing required field '{key}'")
    if not isinstance(value, str):
        raise ValueError(
            f"{where}: '{key}' must be a string, got {type(value).__name__}"
        )
    # Block scalars (`|`, `>`) end with a newline. Stripping keeps the text
    # stable across a round trip so an unchanged file never reads as an edit.
    value = value.strip()
    if not value:
        raise ValueError(f"{where}: '{key}' must be a non-empty string")
    if len(value) > max_len:
        raise ValueError(
            f"{where}: '{key}' must be 1-{max_len} characters "
            f"(got {len(value)})"
        )
    return value


def _status(value: Any, where: str) -> MemoryStatus:
    if value is None:
        return DEFAULT_MEMORY_STATUS
    if isinstance(value, bool):
        raise ValueError(
            f"{where}: 'status' must be enabled or disabled (got {value!r}). "
            f"Quote it if YAML read it as a boolean"
        )
    upper = str(value).strip().upper()
    if upper not in VALID_MEMORY_STATUSES:
        raise ValueError(
            f"{where}: invalid status {value!r}: must be enabled|disabled"
        )
    return MemoryStatus(upper)


def _entities(value: Any, where: str) -> tuple[tuple[str, str], ...]:
    if value is None:
        return ()
    if not isinstance(value, list):
        raise ValueError(f"{where}: 'entities' must be a list")
    if len(value) > MEMORY_ENTITIES_MAX:
        raise ValueError(
            f"{where}: 'entities' accepts at most {MEMORY_ENTITIES_MAX} "
            f"entries (got {len(value)})"
        )
    out: list[tuple[str, str]] = []
    seen: set[tuple[str, str]] = set()
    for i, entity in enumerate(value):
        if not isinstance(entity, dict):
            raise ValueError(
                f"{where}: entities[{i}] must be a mapping with type and value"
            )
        etype = str(entity.get("type") or "").strip().upper()
        if etype not in VALID_MEMORY_ENTITY_TYPES:
            raise ValueError(
                f"{where}: entities[{i}].type must be "
                f"account|device|ip|domain (got {entity.get('type')!r})"
            )
        raw = entity.get("value")
        if raw is None or isinstance(raw, (bool, dict, list)):
            raise ValueError(
                f"{where}: entities[{i}].value must be a string"
            )
        evalue = str(raw).strip()
        if not 1 <= len(evalue) <= MEMORY_ENTITY_VALUE_MAX_LEN:
            raise ValueError(
                f"{where}: entities[{i}].value must be 1-"
                f"{MEMORY_ENTITY_VALUE_MAX_LEN} characters"
            )
        # The API drops a case-insensitive duplicate on write, so the tenant
        # would always hold one entity fewer than the file and the sync would
        # report a change on every run.
        key = (etype, evalue.lower())
        if key in seen:
            raise ValueError(
                f"{where}: entities[{i}] {etype.lower()} {evalue!r} is "
                f"duplicated (matching ignores case)"
            )
        seen.add(key)
        out.append((etype, evalue))
    return tuple(out)


def _labels(value: Any, where: str) -> tuple[str, ...]:
    if value is None:
        return ()
    if not isinstance(value, list):
        raise ValueError(f"{where}: 'labels' must be a list of label names")
    out: list[str] = []
    for i, name in enumerate(value):
        if not isinstance(name, str) or not name.strip():
            raise ValueError(
                f"{where}: labels[{i}] must be a non-empty label name"
            )
        name = name.strip()
        if name.lower() == MANAGED_MEMORY_LABEL:
            raise ValueError(
                f"{where}: labels[{i}] {name!r} is added by the sync to every "
                f"memory it manages; leave it out"
            )
        if name in out:
            raise ValueError(f"{where}: labels[{i}] {name!r} is duplicated")
        out.append(name)
    return tuple(out)


def parse_memory(doc: Any, where: str) -> MemorySpec:
    if not isinstance(doc, dict):
        raise ValueError(f"{where}: a memory file must be a YAML mapping")
    for key in doc:
        if key not in _ALLOWED_FIELDS:
            hint = _FIELD_HINTS.get(key) or (
                f"allowed fields: {', '.join(sorted(_ALLOWED_FIELDS))}"
            )
            raise ValueError(f"{where}: unknown field '{key}': {hint}")
    title = _text(doc, "title", MEMORY_TITLE_MAX_LEN, where)
    description = _text(doc, "description", MEMORY_DESCRIPTION_MAX_LEN, where)
    if "\n" in description or "\r" in description:
        raise ValueError(
            f"{where}: 'description' must be a single line. Use a folded "
            f"scalar ('>-') or put the detail in 'content'"
        )
    return MemorySpec(
        title=title,
        description=description,
        content=_text(doc, "content", MEMORY_CONTENT_MAX_LEN, where),
        status=_status(doc.get("status"), where),
        expires_at=parse_time(doc.get("expiresAt"), where),
        entities=_entities(doc.get("entities"), where),
        labels=_labels(doc.get("labels"), where),
    )


def memory_warnings(spec: MemorySpec, now: datetime | None = None) -> list[str]:
    now = now or datetime.now(timezone.utc)
    if spec.expires_at is not None and spec.expires_at <= now:
        return [
            f"'expiresAt' {spec.expires_at_iso} is in the past. A new memory "
            f"is rejected by the API; an existing one turns EXPIRED and Vega "
            f"agents stop using it. Delete the file if the memory is no "
            f"longer needed"
        ]
    return []


def _entity_payload(spec: MemorySpec) -> list[dict[str, str]]:
    return [{"type": t, "value": v} for t, v in spec.entities]


def to_create_input(spec: MemorySpec, label_ids: list[str]) -> dict[str, Any]:
    payload: dict[str, Any] = {
        "title": spec.title,
        "description": spec.description,
        "content": spec.content,
        "status": spec.status.value,
        "entities": _entity_payload(spec),
        "labelIds": label_ids,
    }
    if spec.expires_at is not None:
        payload["expiresAt"] = spec.expires_at_iso
    return payload


def to_update_input(
    spec: MemorySpec, memory_id: str, label_ids: list[str]
) -> dict[str, Any]:
    # Every field is sent, so the file stays the source of truth: an explicit
    # null removes an expiration, and the entity and label lists replace what
    # is in the tenant.
    return {
        "id": memory_id,
        "title": spec.title,
        "description": spec.description,
        "content": spec.content,
        "status": spec.status.value,
        "expiresAt": spec.expires_at_iso,
        "entities": _entity_payload(spec),
        "labelIds": label_ids,
    }
