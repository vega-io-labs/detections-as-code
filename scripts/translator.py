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

Validation here mirrors the server's own rules (see consts.py) so a bad value
fails the PR check rather than the post-merge sync, where it would roll back
every other detection in the same batch.
"""

from __future__ import annotations

import re
from typing import Any

from .consts import (
    ACTOR_TARGET_FIELDS_MAX,
    DEDUPLICATION_WINDOW_SECONDS_MAX,
    DEFAULT_STATE,
    DEFAULT_TYPE,
    FREQUENCY_INTERVAL_SECONDS_MAX,
    FREQUENCY_INTERVAL_SECONDS_MIN,
    GROUPING_THRESHOLD_MAX,
    GROUPING_THRESHOLD_MIN,
    LOOKBACK_SECONDS_MAX,
    MANDATORY_FIELDS,
    NAME_MAX_LEN,
    REMOVED_FIELDS,
    SEVERITY_MAP,
    VALID_STATES,
    DetectionState,
)

# externalId regex: ^[a-z0-9][a-z0-9._-]{0,127}$ (max 128 chars).
_EXTERNAL_ID_RE = re.compile(r"^[a-z0-9][a-z0-9._-]{0,127}$")
# Cell names become notebook cell names and are referenced from KQL as
# `@Name`. The API restricts them to this set when a detection is *created*
# and does not re-check on update, so detections predating the rule keep
# names with other characters and stay editable. Hence a warning, not a
# rejection: the linter cannot tell a create from an update without the
# tenant, and blocking would make those detections unmanageable here.
_CELL_NAME_RE = re.compile(r"^[A-Za-z0-9 _-]+$")
_MITRE_TECHNIQUE_RE = re.compile(r"^T\d{4}(\.\d{3})?$")
# Fixed-interval shorthand accepted by the scheduler: hours and/or minutes,
# hours first ("5m", "1h", "1h30m"). Seconds and days are NOT units here -
# "30s" and "2d" are rejected as cron expressions further down.
_FIXED_INTERVAL_RE = re.compile(r"^(?:(\d+)h)?(?:(\d+)m)?$")
# `@every <duration>` is handled by the cron parser, which accepts Go duration
# syntax. Only the units that can appear in a detection schedule are listed.
_EVERY_DURATION_RE = re.compile(
    r"^@every\s+(?:(\d+)h)?(?:(\d+)m)?(?:(\d+)s)?$", re.IGNORECASE
)


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


def _reject_removed_fields(detection: dict[str, Any], ext_id: str) -> None:
    for removed, guidance in REMOVED_FIELDS.items():
        if removed in detection:
            raise ValueError(
                f"{ext_id}: '{removed}' is no longer accepted by the "
                f"detection API. {guidance}. Moving over is a behaviour "
                f"change rather than a rename - '{removed}' never affected "
                f"how alerts were produced, and its successors do, so check "
                f"the value still makes sense"
            )


def frequency_interval_seconds(frequency: str) -> int | None:
    """Interval between two runs, or None when it cannot be derived locally.

    Mirrors the server: a bare `<N>h<N>m` shorthand and `@every <duration>` are
    resolvable here; standard 5-field cron expressions and named macros need a
    cron parser, so those return None and skip the interval-derived checks.
    """
    frequency = frequency.strip()
    if not frequency:
        return None

    for pattern, units in (
        (_FIXED_INTERVAL_RE, (3600, 60)),
        (_EVERY_DURATION_RE, (3600, 60, 1)),
    ):
        match = pattern.match(frequency)
        if match is None or not any(match.groups()):
            continue
        return sum(
            int(value) * unit
            for value, unit in zip(match.groups(), units)
            if value is not None
        )
    return None


def _validate_frequency(frequency: str, ext_id: str) -> int | None:
    """Validate the schedule and return its interval in seconds when known."""
    is_fixed = bool(_FIXED_INTERVAL_RE.match(frequency)) and frequency != ""
    is_cron_like = frequency.startswith("@") or len(frequency.split()) == 5
    if not (is_fixed or is_cron_like):
        raise ValueError(
            f"{ext_id}: 'frequencyCron' must be an hour/minute interval "
            f"(e.g. '5m', '1h', '1h30m'), a 5-field cron expression, or an "
            f"@-macro (e.g. '@every 90m', '@daily'). Seconds and days are not "
            f"interval units - use '2m' rather than '120s' and '24h' rather "
            f"than '1d' (got {frequency!r})"
        )

    interval = frequency_interval_seconds(frequency)
    if interval is None:
        return None
    if not (
        FREQUENCY_INTERVAL_SECONDS_MIN
        <= interval
        <= FREQUENCY_INTERVAL_SECONDS_MAX
    ):
        raise ValueError(
            f"{ext_id}: 'frequencyCron' interval is {interval}s; must be "
            f"between {FREQUENCY_INTERVAL_SECONDS_MIN}s and "
            f"{FREQUENCY_INTERVAL_SECONDS_MAX}s"
        )
    return interval


def _validate_grouping(detection: dict[str, Any], ext_id: str) -> None:
    """Check burst-protection settings.

    `groupingField` and `groupingThreshold` are independent: the threshold also
    governs the runs with no grouping field, where exceeding it rolls the whole
    run into a single alert instead of one alert per row.
    """
    grouping_field = detection.get("groupingField")
    if grouping_field is not None and (
        not isinstance(grouping_field, str) or not grouping_field.strip()
    ):
        raise ValueError(
            f"{ext_id}: 'groupingField' must be a non-empty string "
            f"(a normalized field name)"
        )
    threshold = detection.get("groupingThreshold")
    if threshold is not None and (
        not isinstance(threshold, int)
        or isinstance(threshold, bool)
        or not GROUPING_THRESHOLD_MIN <= threshold <= GROUPING_THRESHOLD_MAX
    ):
        raise ValueError(
            f"{ext_id}: 'groupingThreshold' must be an integer between "
            f"{GROUPING_THRESHOLD_MIN} and {GROUPING_THRESHOLD_MAX} "
            f"(got {threshold!r})"
        )


def _validate_entity_fields(detection: dict[str, Any], ext_id: str) -> None:
    for field in ("actorFields", "targetFields"):
        values = _ensure_list(detection.get(field))
        if len(values) > ACTOR_TARGET_FIELDS_MAX:
            raise ValueError(
                f"{ext_id}: '{field}' accepts at most "
                f"{ACTOR_TARGET_FIELDS_MAX} entries (got {len(values)})"
            )
        for i, value in enumerate(values):
            if not isinstance(value, str) or not value.strip():
                raise ValueError(
                    f"{ext_id}: '{field}[{i}]' must be a non-empty string "
                    f"(a normalized field name)"
                )


def _validate_mitre_techniques(detection: dict[str, Any], ext_id: str) -> None:
    for i, value in enumerate(_ensure_list(detection.get("mitreTechniques"))):
        if not isinstance(value, str) or not _MITRE_TECHNIQUE_RE.match(value):
            raise ValueError(
                f"{ext_id}: 'mitreTechniques[{i}]' must look like 'T1078' or "
                f"'T1078.004' (got {value!r})"
            )


def _validate_deduplication_window(value: Any, ext_id: str) -> int:
    if value is None:
        return 0
    if not isinstance(value, int) or isinstance(value, bool):
        raise ValueError(
            f"{ext_id}: 'deduplicationWindowSeconds' must be an integer "
            f"number of seconds (got {value!r})"
        )
    if not 0 <= value <= DEDUPLICATION_WINDOW_SECONDS_MAX:
        raise ValueError(
            f"{ext_id}: 'deduplicationWindowSeconds' must be between 0 and "
            f"{DEDUPLICATION_WINDOW_SECONDS_MAX} (24 hours), got {value}"
        )
    return value


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
        # An uppercase UUID is the common way to land here: `uuidgen` on macOS
        # emits one, and the difference is easy to miss when scanning hex.
        hint = ""
        if _EXTERNAL_ID_RE.match(ext_id.lower()):
            hint = (
                f" It only differs by case - use '{ext_id.lower()}'. "
                f"Note that macOS 'uuidgen' returns an uppercase v4 UUID; "
                f"see the README for a v7 generator."
            )
        raise ValueError(
            f"{ext_id}: 'id' must match ^[a-z0-9][a-z0-9._-]{{0,127}}$ "
            f"(lowercase, alphanumeric + . _ -, 1-128 chars). "
            f"Recommend a UUID v7.{hint}"
        )

    _reject_removed_fields(detection, ext_id)

    name = _require_nonempty_string(detection, "name")
    if len(name) > NAME_MAX_LEN:
        raise ValueError(
            f"{ext_id}: 'name' must be 1-{NAME_MAX_LEN} characters "
            f"(got {len(name)})"
        )

    cells = _build_cells(detection, ext_id)
    frequency = _require_nonempty_string(detection, "frequencyCron").strip()
    interval = _validate_frequency(frequency, ext_id)

    lookback_raw = detection["lookBackSeconds"]
    if not isinstance(lookback_raw, int) or isinstance(lookback_raw, bool):
        raise ValueError(
            f"{ext_id}: 'lookBackSeconds' must be an integer number of "
            f"seconds (got {lookback_raw!r})"
        )
    # A lookback shorter than the schedule leaves gaps between runs, so the
    # server rejects it outright.
    minimum_lookback = interval or 1
    if not minimum_lookback <= lookback_raw <= LOOKBACK_SECONDS_MAX:
        floor_hint = (
            f"the {interval}s 'frequencyCron' interval"
            if interval
            else "1 second"
        )
        raise ValueError(
            f"{ext_id}: 'lookBackSeconds' must be >= {floor_hint} and <= "
            f"{LOOKBACK_SECONDS_MAX} (got {lookback_raw})"
        )

    _validate_mitre_techniques(detection, ext_id)
    _validate_entity_fields(detection, ext_id)
    _validate_grouping(detection, ext_id)

    payload = {
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
        "deduplicationFields": _ensure_list(
            detection.get("deduplicationFields")
        ),
        "deduplicationWindowSeconds": _validate_deduplication_window(
            detection.get("deduplicationWindowSeconds"), ext_id
        ),
        "actorFields": _ensure_list(detection.get("actorFields")),
        "targetFields": _ensure_list(detection.get("targetFields")),
        "cells": cells,
    }
    # Both grouping fields are omitted unless the YAML sets them. The API reads
    # an absent value as "leave unchanged" and cannot tell it apart from an
    # explicit null, so there is no payload that clears them - see
    # docs/fields.md.
    if detection.get("groupingField") is not None:
        payload["groupingField"] = detection["groupingField"].strip()
    if detection.get("groupingThreshold") is not None:
        payload["groupingThreshold"] = detection["groupingThreshold"]
    return payload


def create_only_warnings(detection: dict[str, Any]) -> list[str]:
    """Rules the API applies to new detections but not to updates.

    Reported as warnings because the linter has no tenant access and cannot
    tell which of the two a given YAML will become. Ignoring one on a brand
    new detection costs the whole sync batch, since a rejected create rolls
    back every detection sent with it.
    """
    warnings: list[str] = []
    cells = _resolve_cells_field(detection) or []
    for i, cell in enumerate(cells):
        name = cell.get("name") if isinstance(cell, dict) else None
        if isinstance(name, str) and name and not _CELL_NAME_RE.match(name):
            warnings.append(
                f"cells[{i}].name {name!r} contains characters the API "
                f"rejects when creating a detection (allowed: letters, "
                f"digits, spaces, '_' and '-'). Fine if this detection "
                f"already exists in the tenant; it will fail the sync if it "
                f"is new"
            )
    return warnings


def yaml_to_update_input(detection: dict[str, Any]) -> dict[str, Any]:
    create = yaml_to_create_input(detection)
    return {
        **create,
        "state": _state_to_enum(detection.get("state")).value,
    }


def yaml_state(detection: dict[str, Any]) -> DetectionState:
    return _state_to_enum(detection.get("state"))
