"""Translate tenant state back into the files of this repository.

The forward direction (translator.py and the reconcilers) turns files into API
payloads and decides what to write by diffing them against the tenant. This
module is its mirror: given an object as the API returns it, it produces the
file whose forward payload is a no-op against that object, so a repository
that merges the result has nothing left to sync.

Existing files are edited in place with ruamel.yaml, which keeps their
comments, key order and quoting. Only the keys whose values moved are touched,
and a list or text that the forward sync already considers equal is left as
the author wrote it.
"""

from __future__ import annotations

import io
import re
from collections import Counter
from datetime import datetime, timezone
from typing import Any, Callable

import yaml
from ruamel.yaml import YAML
from ruamel.yaml.comments import CommentedMap, CommentedSeq
from ruamel.yaml.scalarstring import (
    DoubleQuotedScalarString,
    LiteralScalarString,
    ScalarString,
)

from .consts import MANAGED_MEMORY_LABEL, SEVERITY_MAP, UNCLEARABLE_TEXT_FIELDS
from .labels import label_key
from .memory_reconciler import is_no_op as memory_is_no_op
from .memory_translator import MemorySpec, parse_memory
from .reconciler import (
    frequency_equal,
    is_no_op_update,
    normalise_cell_query,
)
from .skill_reconciler import is_no_op as skill_is_no_op
from .skill_translator import SkillSpec, parse_skill, split_frontmatter
from .translator import frequency_interval_seconds, yaml_to_update_input
from .utils import format_utc, parse_time

DETECTION_KEY_ORDER: tuple[str, ...] = (
    "id",
    "name",
    "severity",
    "state",
    "frequencyCron",
    "lookBackSeconds",
    "mode",
    "logicDescription",
    "attackScenario",
    "mitreTechniques",
    "references",
    "deduplicationFields",
    "deduplicationWindowSeconds",
    "groupingField",
    "groupingThreshold",
    "actorFields",
    "targetFields",
    "skillIds",
    "query",
    "cells",
    "detectionCells",
)
SKILL_KEY_ORDER: tuple[str, ...] = ("id", "name", "description", "type")
MEMORY_KEY_ORDER: tuple[str, ...] = (
    "title",
    "description",
    "content",
    "status",
    "expiresAt",
    "entities",
    "labels",
)

# The API's default: a file that does not set the threshold gets it.
DEFAULT_GROUPING_THRESHOLD = 10

# Always written as a block scalar, even on one line: they are KQL and prose
# that people read and edit in place.
_BLOCK_TEXT_KEYS = frozenset({"query", "content"})

_SEVERITY_INT = {v: k for k, v in SEVERITY_MAP.items() if isinstance(k, int)}
_SLUG_RE = re.compile(r"[^a-z0-9]+")
_SLUG_MAX_LEN = 80


class ExportError(ValueError):
    """The tenant object cannot be written as a file the forward sync accepts."""


def slug(text: str) -> str:
    return _SLUG_RE.sub("-", text.lower()).strip("-")[:_SLUG_MAX_LEN].strip("-")


# --------------------------------------------------------------------------
# Detections
# --------------------------------------------------------------------------


def _severity(vega_value: str, previous: Any) -> Any:
    if isinstance(previous, str):
        if SEVERITY_MAP.get(previous.lower()) == vega_value:
            return previous
        return vega_value if previous.isupper() else vega_value.lower()
    return _SEVERITY_INT[vega_value]


def _frequency(vega_value: str | None, previous: Any) -> str:
    vega_value = (vega_value or "").strip()
    if isinstance(previous, str) and frequency_equal(previous.strip(), vega_value):
        return previous
    interval = frequency_interval_seconds(vega_value)
    if interval is None or not vega_value.lower().startswith("@every"):
        return vega_value
    hours, rest = divmod(interval, 3600)
    minutes, seconds = divmod(rest, 60)
    if seconds:
        return vega_value
    if not minutes:
        return f"{hours}h"
    return f"{hours}h{minutes}m" if hours else f"{minutes}m"


def _keep_order(
    values: list[Any], previous: Any, key: Callable[[Any], Any] = str
) -> list[Any]:
    """`values` in the file's order: items the file already has stay where
    they are, as the file spells them, and new ones are appended."""
    if not isinstance(previous, list):
        return values
    remaining = Counter(key(v) for v in values)
    kept = []
    for item in previous:
        if remaining[key(item)] > 0:
            remaining[key(item)] -= 1
            kept.append(item)
    for item in values:
        if remaining[key(item)] > 0:
            remaining[key(item)] -= 1
            kept.append(item)
    return kept


def _set_or_drop(
    doc: dict[str, Any],
    key: str,
    value: Any,
    is_default: Callable[[Any], bool],
    existing: dict[str, Any],
) -> None:
    """Write `value`; at its default, only keep a default the file spells out.

    A template file says `references: []` and `mode: "alert"` on purpose, so
    those stay. A value the tenant cleared back to the default goes away with
    its key rather than lingering as `references: []`.
    """
    if not is_default(value):
        doc[key] = value
    elif key in existing and is_default(existing[key]):
        doc[key] = existing[key]


def _empty(value: Any) -> bool:
    return value is None or value == []


def _set_list(
    doc: dict[str, Any], key: str, values: list[Any], existing: dict[str, Any]
) -> None:
    _set_or_drop(doc, key, values, _empty, existing)


def _grouping(
    doc: dict[str, Any], vega: dict[str, Any], existing: dict[str, Any]
) -> None:
    grouping_field = vega.get("groupingField")
    if grouping_field is not None:
        doc["groupingField"] = grouping_field
    threshold = vega.get("groupingThreshold")
    if threshold is not None:
        _set_or_drop(
            doc,
            "groupingThreshold",
            threshold,
            lambda v: grouping_field is None and v == DEFAULT_GROUPING_THRESHOLD,
            existing,
        )


def _cell_text(vega_query: str | None, previous: Any) -> str:
    if isinstance(previous, str) and normalise_cell_query(
        previous
    ) == normalise_cell_query(vega_query):
        return previous
    return normalise_cell_query(vega_query)


def _single_trigger(cells: list[dict[str, Any]]) -> bool:
    return (
        len(cells) == 1
        and bool(cells[0].get("trigger"))
        and cells[0].get("name") == "trigger"
    )


def _cells(
    doc: dict[str, Any], vega_cells: list[dict[str, Any]], existing: dict[str, Any]
) -> None:
    cells_key = next(
        (k for k in ("cells", "detectionCells") if isinstance(existing.get(k), list)),
        None,
    )
    if cells_key is None and (
        "query" in existing or not existing
    ) and _single_trigger(vega_cells):
        doc["query"] = _cell_text(vega_cells[0].get("query"), existing.get("query"))
        return
    cells_key = cells_key or "cells"
    previous = {
        c.get("name"): c
        for c in existing.get(cells_key) or []
        if isinstance(c, dict)
    }
    by_name = {c.get("name"): c for c in vega_cells}
    ordered = [n for n in previous if n in by_name] + [
        n for n in by_name if n not in previous
    ]
    out: list[dict[str, Any]] = []
    for name in ordered:
        vega_cell = by_name[name]
        prev = previous.get(name) or {}
        cell: dict[str, Any] = {
            "name": name,
            "query": _cell_text(vega_cell.get("query"), prev.get("query")),
        }
        if vega_cell.get("trigger") or "trigger" in prev:
            cell["trigger"] = bool(vega_cell.get("trigger"))
        out.append(cell)
    doc[cells_key] = out


def detection_file(
    vega: dict[str, Any],
    existing: dict[str, Any] | None,
    skill_external_ids: dict[str, str],
) -> dict[str, Any]:
    """The YAML mapping whose forward payload is a no-op against `vega`.

    `skill_external_ids` maps tenant skill ids to the `id` of their SKILL.md in
    this repository; skills without a file keep their tenant id.
    """
    existing = existing or {}
    doc: dict[str, Any] = {"id": vega["externalId"], "name": vega["name"]}
    doc["severity"] = _severity(vega["severity"], existing.get("severity"))
    doc["state"] = str(vega.get("state") or "ENABLED").lower()
    doc["frequencyCron"] = _frequency(
        vega.get("frequencyCron"), existing.get("frequencyCron")
    )
    doc["lookBackSeconds"] = vega["lookBackSeconds"]
    _set_or_drop(
        doc,
        "mode",
        str(vega.get("mode") or "ALERT").lower(),
        lambda v: v is None or str(v).strip().lower() == "alert",
        existing,
    )
    for key in UNCLEARABLE_TEXT_FIELDS:
        if vega.get(key):
            doc[key] = vega[key]
    for key in ("mitreTechniques", "references", "deduplicationFields"):
        _set_list(
            doc, key, _keep_order(list(vega.get(key) or []), existing.get(key)), existing
        )
    _set_or_drop(
        doc,
        "deduplicationWindowSeconds",
        vega.get("deduplicationWindowSeconds") or 0,
        lambda v: not v,
        existing,
    )
    _grouping(doc, vega, existing)
    for key in ("actorFields", "targetFields"):
        _set_list(doc, key, list(vega.get(key) or []), existing)
    skill_ids = sorted(
        {skill_external_ids.get(s["id"], s["id"]) for s in vega.get("skills") or []}
    )
    _set_list(doc, "skillIds", _keep_order(skill_ids, existing.get("skillIds")), existing)
    _cells(doc, list(vega.get("cells") or []), existing)
    return doc


def detection_payload(
    doc: dict[str, Any], skill_tenant_ids: dict[str, str]
) -> dict[str, Any]:
    """The update payload the forward sync would diff `doc` with.

    `skill_tenant_ids` maps repository skill ids to tenant ids, the swap the
    forward sync makes before it compares. Raises ValueError like the sync
    when the file is not valid.
    """
    payload = yaml_to_update_input(doc)
    payload["skillIds"] = [
        skill_tenant_ids.get(str(s).strip(), str(s).strip())
        for s in payload["skillIds"]
    ]
    return payload


def detection_matches(
    doc: dict[str, Any], vega: dict[str, Any], skill_tenant_ids: dict[str, str]
) -> bool:
    """Whether the forward sync would skip `doc` as a no-op against `vega`."""
    try:
        payload = detection_payload(doc, skill_tenant_ids)
    except ValueError:
        return False
    return is_no_op_update(payload, vega)


# --------------------------------------------------------------------------
# Skills
# --------------------------------------------------------------------------


def skill_frontmatter(
    vega: dict[str, Any], existing: dict[str, Any] | None
) -> dict[str, Any]:
    existing = existing or {}
    doc: dict[str, Any] = {
        "id": vega["externalId"],
        "name": (vega.get("name") or "").strip(),
        "description": (vega.get("description") or "").strip(),
        "type": str(vega.get("type") or "").lower(),
    }
    previous_id = existing.get("id")
    if isinstance(previous_id, str) and previous_id.strip().lower() == doc["id"]:
        doc["id"] = previous_id
    previous_type = existing.get("type")
    if isinstance(previous_type, str) and previous_type.strip().upper().replace(
        "-", "_"
    ) == str(vega.get("type") or ""):
        doc["type"] = previous_type
    for key in ("name", "description"):
        previous = existing.get(key)
        if isinstance(previous, str) and previous.strip() == doc[key]:
            doc[key] = previous
    return doc


def skill_file(vega: dict[str, Any], existing_text: str | None) -> str:
    body = (vega.get("instructions") or "").strip()
    parts = split_frontmatter(existing_text) if existing_text is not None else None
    frontmatter_text: str | None = None
    existing_doc: dict[str, Any] | None = None
    if parts is not None:
        frontmatter_text = parts[0]
        loaded = yaml.safe_load(frontmatter_text)
        existing_doc = loaded if isinstance(loaded, dict) else None
        if existing_doc is not None and parts[1].strip() == body:
            body = parts[1].strip("\n")
    doc = skill_frontmatter(vega, existing_doc)
    frontmatter = render(doc, frontmatter_text, SKILL_KEY_ORDER).rstrip("\n")
    return f"---\n{frontmatter}\n---\n\n{body}\n"


def skill_matches(spec: SkillSpec, vega: dict[str, Any]) -> bool:
    return skill_is_no_op(spec, vega)


# --------------------------------------------------------------------------
# Memories
# --------------------------------------------------------------------------


def _expires_text(value: datetime, previous: Any) -> Any:
    if previous is not None:
        try:
            if parse_time(previous, "", "expiresAt") == value:
                return previous
        except ValueError:
            pass
    utc = value.astimezone(timezone.utc)
    if (utc.hour, utc.minute, utc.second) == (0, 0, 0):
        return utc.strftime("%Y-%m-%d")
    return format_utc(value) or ""


def _entity_key(entity: Any) -> Any:
    if not isinstance(entity, dict):
        return repr(entity)
    return str(entity.get("type") or "").upper(), str(entity.get("value") or "").strip().lower()


def _label_key(label: Any) -> str:
    return label_key(str(label))


def _text_or_previous(vega_value: Any, previous: Any) -> str:
    value = str(vega_value or "").strip()
    if isinstance(previous, str) and previous.strip() == value:
        return previous
    return value


def memory_file(
    vega: dict[str, Any], existing: dict[str, Any] | None
) -> dict[str, Any]:
    """The YAML mapping whose forward payload is a no-op against `vega`."""
    existing = existing or {}
    doc: dict[str, Any] = {
        "title": _text_or_previous(vega.get("title"), existing.get("title")),
        "description": _text_or_previous(
            vega.get("description"), existing.get("description")
        ),
        "content": _text_or_previous(vega.get("content"), existing.get("content")),
    }
    _set_or_drop(
        doc,
        "status",
        "enabled" if vega.get("enabled") else "disabled",
        lambda v: v is None or str(v).strip().lower() == "enabled",
        existing,
    )
    expires = parse_time(vega.get("expiresAt"), doc["title"], "expiresAt")
    if expires is not None:
        doc["expiresAt"] = _expires_text(expires, existing.get("expiresAt"))
    entities = [
        {"type": str(e["type"]).lower(), "value": str(e["value"]).strip()}
        for e in vega.get("entities") or []
    ]
    _set_list(doc, "entities", _keep_order(entities, existing.get("entities"), _entity_key), existing)
    labels = [
        label["name"]
        for label in vega.get("labels") or []
        if label.get("name") and label_key(label["name"]) != MANAGED_MEMORY_LABEL
    ]
    _set_list(doc, "labels", _keep_order(labels, existing.get("labels"), _label_key), existing)
    return doc


def memory_matches(
    spec: MemorySpec,
    vega: dict[str, Any],
    label_ids: dict[str, str],
    managed_label_id: str,
) -> bool:
    ids = [label_ids[label_key(n)] for n in spec.labels if label_key(n) in label_ids]
    if len(ids) != len(spec.labels):
        return False
    return memory_is_no_op(spec, vega, [*ids, managed_label_id])


# --------------------------------------------------------------------------
# Rendering
# --------------------------------------------------------------------------


def _yaml() -> YAML:
    y = YAML()
    y.preserve_quotes = True
    y.width = 4096
    y.indent(mapping=2, sequence=4, offset=2)
    return y


def _block_safe(text: str) -> bool:
    return all(line == line.rstrip() for line in text.split("\n"))


def _fresh_text(value: str, key: str | None) -> Any:
    if ("\n" in value or key in _BLOCK_TEXT_KEYS) and _block_safe(value):
        return LiteralScalarString(value)
    return DoubleQuotedScalarString(value)


def _fresh(value: Any, key: str | None = None) -> Any:
    if isinstance(value, bool) or value is None:
        return value
    if isinstance(value, str):
        return _fresh_text(value, key)
    if isinstance(value, (int, float)):
        return value
    if isinstance(value, dict):
        out = CommentedMap()
        for k, v in value.items():
            out[k] = _fresh(v, k)
        return out
    if isinstance(value, list):
        seq = CommentedSeq(_fresh(v, key) for v in value)
        if not value:
            seq.fa.set_flow_style()
        return seq
    return value


def _styled_text(value: str, current: Any, key: str | None) -> Any:
    if isinstance(current, LiteralScalarString) and _block_safe(value):
        return LiteralScalarString(value)
    if "\n" not in value:
        if isinstance(current, ScalarString):
            return type(current)(value)
        if isinstance(current, str):
            return value
    return _fresh_text(value, key)


def _item_key(item: Any) -> Any:
    if isinstance(item, dict):
        if "name" in item:
            return str(item.get("name"))
        return _entity_key(item)
    return str(item)


def _styled_item(value: Any, sample: Any, key: str | None) -> Any:
    if isinstance(value, str) and isinstance(sample, ScalarString) and "\n" not in value:
        return type(sample)(value)
    return _fresh(value, key)


def _update_seq(current: Any, values: list[Any], key: str | None) -> Any:
    """Bring a list to `values`, editing the file's own list in place.

    Items that stay are left where they are, with their comments; items the
    tenant dropped are removed and new ones appended. Only when the result
    would still be in a different order (the ordered actor/target fields) is
    the list rebuilt.
    """
    if not isinstance(current, CommentedSeq):
        return _fresh(values, key)
    if not values:
        empty = CommentedSeq()
        empty.fa.set_flow_style()
        return empty
    sample = next((item for item in current if isinstance(item, ScalarString)), None)

    remaining = Counter(_item_key(v) for v in values)
    for index in reversed(range(len(current))):
        item_key = _item_key(current[index])
        if remaining[item_key] > 0:
            remaining[item_key] -= 1
        else:
            del current[index]
    present = Counter(_item_key(item) for item in current)
    for value in values:
        if present[_item_key(value)] > 0:
            present[_item_key(value)] -= 1
        else:
            current.append(_styled_item(value, sample, key))

    maps: dict[Any, list[CommentedMap]] = {}
    for item in current:
        if isinstance(item, CommentedMap):
            maps.setdefault(_item_key(item), []).append(item)
    for value in values:
        if isinstance(value, dict) and maps.get(_item_key(value)):
            _update_map(maps[_item_key(value)].pop(0), value, tuple(value.keys()))

    if [_item_key(item) for item in current] == [_item_key(v) for v in values]:
        return current
    by_key: dict[Any, list[Any]] = {}
    for item in current:
        by_key.setdefault(_item_key(item), []).append(item)
    rebuilt = CommentedSeq(by_key[_item_key(v)].pop(0) for v in values)
    if current.fa.flow_style():
        rebuilt.fa.set_flow_style()
    return rebuilt


def _plain(value: Any) -> Any:
    if isinstance(value, dict):
        return {k: _plain(v) for k, v in value.items()}
    if isinstance(value, list):
        return [_plain(v) for v in value]
    if isinstance(value, str):
        return str(value)
    return value


def _insert_ordered(
    data: CommentedMap, key: str, value: Any, order: tuple[str, ...]
) -> None:
    rank = {k: i for i, k in enumerate(order)}
    position = 0
    for i, existing in enumerate(data.keys()):
        if existing in rank and rank[existing] <= rank[key]:
            position = i + 1
    data.insert(position, key, value)


def _update_map(data: CommentedMap, doc: dict[str, Any], order: tuple[str, ...]) -> None:
    for key in list(data.keys()):
        if key in order and key not in doc:
            del data[key]
    for key in order:
        if key not in doc:
            continue
        value = doc[key]
        if key not in data:
            _insert_ordered(data, key, _fresh(value, key), order)
            continue
        current = data[key]
        if _plain(current) == _plain(value):
            continue
        if isinstance(value, str):
            data[key] = _styled_text(value, current, key)
        elif isinstance(value, list):
            data[key] = _update_seq(current, value, key)
        elif isinstance(value, dict) and isinstance(current, CommentedMap):
            _update_map(current, value, tuple(value.keys()))
        else:
            data[key] = _fresh(value, key)


def render(
    doc: dict[str, Any], existing_text: str | None, order: tuple[str, ...]
) -> str:
    """Serialise `doc`, editing `existing_text` in place when it is given."""
    y = _yaml()
    data: Any = None
    if existing_text is not None and existing_text.strip():
        data = y.load(existing_text)
    if not isinstance(data, CommentedMap):
        data = CommentedMap()
    _update_map(data, doc, order)
    buf = io.StringIO()
    y.dump(data, buf)
    return buf.getvalue()


def load_detection_doc(text: str) -> dict[str, Any]:
    doc = yaml.safe_load(text)
    if not isinstance(doc, dict):
        raise ExportError("the rendered detection is not a YAML mapping")
    return doc


def verify_detection(
    text: str, vega: dict[str, Any], skill_tenant_ids: dict[str, str]
) -> None:
    doc = load_detection_doc(text)
    try:
        payload = detection_payload(doc, skill_tenant_ids)
    except ValueError as e:
        # The tenant accepted something the PR check would not, so the file
        # cannot go through a pull request; the sync would reject it too.
        raise ExportError(
            f"{vega['externalId']}: the detection as it is in the tenant does "
            f"not pass this repository's validation: {e}"
        ) from None
    if str(doc.get("id")) != vega["externalId"] or not is_no_op_update(
        payload, vega
    ):
        raise ExportError(
            f"{vega['externalId']}: the exported file would still differ from "
            f"the tenant; this is a bug in the exporter, not in the detection"
        )


def verify_skill(text: str, vega: dict[str, Any], where: str) -> None:
    spec = parse_skill(text, where)
    if spec.external_id != vega["externalId"] or not skill_matches(spec, vega):
        raise ExportError(
            f"{vega['externalId']}: the exported skill would still differ from "
            f"the tenant; this is a bug in the exporter, not in the skill"
        )


def verify_memory(
    text: str,
    vega: dict[str, Any],
    where: str,
    label_ids: dict[str, str],
    managed_label_id: str,
) -> None:
    spec = parse_memory(yaml.safe_load(text), where)
    if not memory_matches(spec, vega, label_ids, managed_label_id):
        raise ExportError(
            f"{spec.title!r}: the exported memory would still differ from the "
            f"tenant; this is a bug in the exporter, not in the memory"
        )
