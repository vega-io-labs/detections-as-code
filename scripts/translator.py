"""Translate the customer YAML schema to Vega API payloads.

Mapping:
  id     -> externalId
  query  -> cells: [{ name: "trigger", query, trigger: true }]
  cells  -> cells (or `detectionCells` alias)
  state  -> DetectionState enum value
  severity -> DetectionSeverity enum value (accepts int 1-4 or LOW|MEDIUM|HIGH|CRITICAL)

Omitted fields:
  mitreTactics    : derived server-side from mitreTechniques.
  dataSourcesIds  : derived from the KQL table selector.
  tags            : UI-managed.
"""

from __future__ import annotations

import re
from typing import Any

from .consts import (
    DEFAULT_STATE,
    DEFAULT_TYPE,
    MANDATORY_FIELDS,
    SEVERITY_MAP,
    VALID_STATES,
    DetectionState,
)

# externalId regex: ^[a-z0-9][a-z0-9._-]{0,127}$ (max 128 chars).
_EXTERNAL_ID_RE = re.compile(r"^[a-z0-9][a-z0-9._-]{0,127}$")
_CELL_NAME_RE = re.compile(r"^[^@].*$")  # must not start with '@'
_NAME_MAX_LEN = 200


def _severity_to_enum(value: Any) -> str:
    key = value.lower() if isinstance(value, str) else value
    if key in SEVERITY_MAP:
        return SEVERITY_MAP[key]
    raise ValueError(
        f"invalid severity {value!r}: must be 1-4 or LOW|MEDIUM|HIGH|CRITICAL"
    )


def _state_to_enum(value: Any) -> DetectionState:
    if value is None:
        return DEFAULT_STATE
    upper = str(value).upper().replace("-", "_")
    if upper == "TEST":
        upper = "TEST_MODE"
    if upper not in VALID_STATES:
        raise ValueError(
            f"invalid state {value!r}: must be enabled|disabled|test_mode"
        )
    return DetectionState(upper)


def _ensure_list(value: Any) -> list:
    if value is None:
        return []
    if isinstance(value, (list, tuple)):
        return list(value)
    return [value]


def _resolve_cells_field(detection: dict[str, Any]) -> list | None:
    """Return the cells list from either `cells` or `detectionCells` alias."""
    for key in ("cells", "detectionCells"):
        if (value := detection.get(key)) and isinstance(value, list):
            return value
    return None


def _require_nonempty_string(detection: dict[str, Any], field: str) -> str:
    value = detection.get(field)
    if value is None:
        raise ValueError(
            f"{detection.get('id', '<no id>')}: missing required field '{field}'"
        )
    if not isinstance(value, str):
        raise ValueError(
            f"{detection['id']}: '{field}' must be a string, got "
            f"{type(value).__name__}"
        )
    if not value.strip():
        raise ValueError(
            f"{detection['id']}: '{field}' must be a non-empty string"
        )
    return value


def _build_cells(detection: dict[str, Any], ext_id: str) -> list[dict[str, Any]]:
    has_query = bool(detection.get("query"))
    cells_list = _resolve_cells_field(detection)
    has_cells = cells_list is not None

    if has_query and has_cells:
        raise ValueError(
            f"{ext_id}: provide either 'query' (single-cell) OR 'cells' "
            f"(multi-cell), not both"
        )
    if not has_query and not has_cells:
        raise ValueError(
            f"{ext_id}: missing required field 'query' "
            f"(or 'cells' for multi-cell detections)"
        )

    if has_query:
        query_text = _require_nonempty_string(detection, "query")
        return [{"name": "trigger", "query": query_text, "trigger": True}]

    out: list[dict[str, Any]] = []
    trigger_count = 0
    seen_names: set[str] = set()
    for i, cell in enumerate(cells_list):
        if not isinstance(cell, dict):
            raise ValueError(
                f"{ext_id}: cells[{i}] must be a mapping with name/query"
            )
        name = cell.get("name")
        if not isinstance(name, str) or not name.strip():
            raise ValueError(
                f"{ext_id}: cells[{i}].name is required and must be non-empty"
            )
        if not _CELL_NAME_RE.match(name):
            raise ValueError(
                f"{ext_id}: cells[{i}].name {name!r} must not start with '@'"
            )
        if name in seen_names:
            raise ValueError(
                f"{ext_id}: cells[{i}].name {name!r} is duplicated"
            )
        seen_names.add(name)
        cell_query = cell.get("query")
        if not isinstance(cell_query, str) or not cell_query.strip():
            raise ValueError(
                f"{ext_id}: cells[{i}].query is required and must be non-empty"
            )
        is_trigger = bool(cell.get("trigger", False))
        if is_trigger:
            trigger_count += 1
        out.append({"name": name, "query": cell_query, "trigger": is_trigger})

    if trigger_count != 1:
        raise ValueError(
            f"{ext_id}: exactly one cell must have 'trigger: true' "
            f"(got {trigger_count})"
        )
    return out


def yaml_to_create_input(detection: dict[str, Any]) -> dict[str, Any]:
    for field in MANDATORY_FIELDS:
        if field not in detection or detection[field] in (None, ""):
            raise ValueError(
                f"{detection.get('id', '<no id>')}: missing required field "
                f"'{field}'"
            )

    ext_id = str(detection["id"]).strip()
    if not _EXTERNAL_ID_RE.match(ext_id):
        raise ValueError(
            f"{ext_id}: 'id' must match ^[a-z0-9][a-z0-9._-]{{0,127}}$ "
            f"(lowercase, alphanumeric + . _ -, 1-128 chars). "
            f"Recommend a UUID v7."
        )

    name = _require_nonempty_string(detection, "name")
    if len(name) > _NAME_MAX_LEN:
        raise ValueError(
            f"{ext_id}: 'name' must be 1-{_NAME_MAX_LEN} characters "
            f"(got {len(name)})"
        )

    cells = _build_cells(detection, ext_id)
    frequency = _require_nonempty_string(detection, "frequencyCron")

    lookback_raw = detection["lookBackSeconds"]
    if not isinstance(lookback_raw, int) or lookback_raw <= 0:
        raise ValueError(
            f"{ext_id}: 'lookBackSeconds' must be a positive integer "
            f"(got {lookback_raw!r})"
        )

    return {
        "externalId": ext_id,
        "name": name,
        "severity": _severity_to_enum(detection["severity"]),
        "frequencyCron": frequency,
        "lookBackSeconds": lookback_raw,
        "type": str(detection.get("type", DEFAULT_TYPE)).upper(),
        "mitreTechniques": _ensure_list(detection.get("mitreTechniques")),
        "logicDescription": detection.get("logicDescription") or "",
        "attackScenario": detection.get("attackScenario") or "",
        "references": _ensure_list(detection.get("references")),
        "groupingFields": _ensure_list(detection.get("groupingFields")),
        "groupingDurationSeconds": detection.get("groupingDurationSeconds"),
        "cells": cells,
    }


def yaml_to_update_input(detection: dict[str, Any]) -> dict[str, Any]:
    create = yaml_to_create_input(detection)
    return {
        **create,
        "state": _state_to_enum(detection.get("state")).value,
    }


def yaml_state(detection: dict[str, Any]) -> DetectionState:
    return _state_to_enum(detection.get("state"))
