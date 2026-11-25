"""Declarative reconciler: make Vega state match the YAML directory.

Each run, regardless of what changed in git:
1. Load every YAML in detections/.
2. Fetch every detection from Vega.
3. Classify by externalId: create / update / delete.
4. Skip no-op updates by comparing the desired payload to the current Vega state.
5. Apply creates and updates in chunks of BATCH_SIZE. Each call is one
   transaction: the API returns a per-detection `results` array that names the
   offending rules, but a single invalid detection rolls the whole chunk back.
   Deletes are single-shot (the API has no bulk delete).
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Iterable

import yaml

from .client import MODIFY_LABELS_MAX, VegaAPIError, VegaClient
from .consts import MANAGED_LABEL, UNCLEARABLE_TEXT_FIELDS
from .labels import ManagedLabel, is_managed_label
from .plan import (
    ActionKind,
    ActionResult,
    Blocked,
    Plan,
    Planned,
    SyncReport,
    Write,
)
from .translator import (
    frequency_interval_seconds,
    is_library_file,
    library_state_input,
    yaml_to_create_input,
    yaml_to_update_input,
)
from .utils import UniqueKey, chunks, load_unique, yaml_files

BATCH_SIZE = 100  # createDetections / updateDetections cap per call


@dataclass
class DetectionPlan(Plan):
    # Library detections go through setLibraryDetectionsState, which adds one
    # that is missing and moves one that is there, so both lists share a call.
    library_adds: list[Write] = field(default_factory=list)
    library_states: list[Write] = field(default_factory=list)

    def summary(self) -> str:
        return (
            f"{super().summary()} "
            f"library_adds={len(self.library_adds)} "
            f"library_states={len(self.library_states)}"
        )


def _planned(payload: dict[str, Any]) -> Write:
    return Planned(payload["externalId"], payload["name"], payload)


def _load_detection_file(path: Path) -> dict[str, Any] | None:
    with open(path, "r", encoding="utf-8") as fh:
        doc = yaml.safe_load(fh)
    if doc is not None and "id" not in doc:
        raise ValueError(f"{path}: YAML missing required 'id'")
    return doc


def load_yaml_detections(detections_dirs: Iterable[Path]) -> list[dict[str, Any]]:
    return load_unique(
        (f for d in detections_dirs for f in yaml_files(d)),
        _load_detection_file,
        [UniqueKey("id", lambda doc: str(doc["id"]))],
    )


# Fields that meaningfully describe a detection. If all of these match between
# the YAML payload and the current Vega state, the update is a no-op.
_UPDATE_DIFF_FIELDS = (
    "name",
    "severity",
    "state",
    "mode",
    "lookBackSeconds",
    "mitreTechniques",
    "references",
    "deduplicationFields",
)

# actorFields/targetFields are priority-ordered, so reordering is a real change
# and they must not go through the order-insensitive list compare above.
_UPDATE_DIFF_ORDERED_FIELDS = (
    "actorFields",
    "targetFields",
)

# None of these can be cleared through the API: the grouping pair because an
# omitted value and an explicit null both read as "leave unchanged", the two
# descriptions because an empty string is rejected. They are therefore only
# compared when the YAML actually sets them - otherwise a detection that once
# had a value would report a diff on every run and never converge.
_UPDATE_DIFF_UNCLEARABLE_FIELDS = (
    "groupingField",
    "groupingThreshold",
    *UNCLEARABLE_TEXT_FIELDS,
)


def frequency_equal(yaml_value: str, vega_value: str | None) -> bool:
    # A fixed interval is stored as `@every <expr>`, so `60m` reads back as
    # `@every 60m`. Compare the resolved interval where possible so `1h` and
    # `60m` also count as equal; fall back to the literal text for cron
    # expressions, which are stored verbatim. Otherwise every run sees a
    # phantom diff and pushes a new detection version.
    if vega_value is None:
        return False

    yaml_interval = frequency_interval_seconds(yaml_value)
    if yaml_interval is not None:
        vega_interval = frequency_interval_seconds(vega_value)
        if vega_interval is not None:
            return yaml_interval == vega_interval

    return (yaml_value or "").strip() == (vega_value or "").strip()


# A cell reference is stored in canonical form: the `@other-cell` a human
# writes comes back as `@cells:<ref>/other-cell`, where <ref> is assigned by
# the server. Comparing the raw text would therefore report a diff on every
# multi-cell detection forever, so both sides are reduced to the bare name
# first. Cell names are unique within a detection, which is what makes the
# short form unambiguous. Data-source selectors are left alone: the API
# stores those exactly as written.
_CELL_REFERENCE_RE = re.compile(r"@cells:[A-Za-z0-9_-]+/")


def normalise_cell_query(query: str | None) -> str:
    return _CELL_REFERENCE_RE.sub("@", (query or "").strip())


def query_cells(cells: list[dict[str, Any]] | None) -> list[dict[str, Any]]:
    # Triage and investigation cells hold skills, not KQL. The API lists them
    # with an empty query, and a file cannot hold an empty query, so they are
    # left out on read. Every detection added from the Vega library has one.
    return [
        c for c in cells or [] if c.get("trigger") or (c.get("query") or "").strip()
    ]


def _cells_equal(yaml_cells: list, vega_cells: list | None) -> bool:
    if vega_cells is None:
        return False
    vega_cells = query_cells(vega_cells)
    if len(yaml_cells) != len(vega_cells):
        return False
    yk = sorted(yaml_cells, key=lambda c: c.get("name") or "")
    vk = sorted(vega_cells, key=lambda c: c.get("name") or "")
    for a, b in zip(yk, vk):
        if a.get("name") != b.get("name"):
            return False
        if normalise_cell_query(a.get("query")) != normalise_cell_query(
            b.get("query")
        ):
            return False
        if bool(a.get("trigger")) != bool(b.get("trigger")):
            return False
    return True


def is_no_op_update(
    payload: dict[str, Any], vega_state: dict[str, Any]
) -> bool:
    for f in _UPDATE_DIFF_FIELDS:
        a, b = payload.get(f), vega_state.get(f)
        if isinstance(a, list) and isinstance(b, list):
            if sorted(map(str, a)) != sorted(map(str, b)):
                return False
        elif a != b:
            return False
    for f in _UPDATE_DIFF_ORDERED_FIELDS:
        if (payload.get(f) or []) != (vega_state.get(f) or []):
            return False
    # The API has returned the same skill several times on one detection, so
    # the attached set is what matters, not the list.
    vega_skill_ids = {s["id"] for s in vega_state.get("skills") or []}
    if set(payload.get("skillIds") or []) != vega_skill_ids:
        return False
    # Vega reports a disabled window as either null or 0.
    if (payload.get("deduplicationWindowSeconds") or 0) != (
        vega_state.get("deduplicationWindowSeconds") or 0
    ):
        return False
    # Only compared when the payload carries them: absent means the UI owns it.
    if "isAlwaysEscalatedToIncident" in payload and payload[
        "isAlwaysEscalatedToIncident"
    ] != bool(vega_state.get("isAlwaysEscalatedToIncident")):
        return False
    if "webhookIds" in payload and set(payload["webhookIds"]) != {
        str(w).lower() for w in vega_state.get("webhookIds") or []
    }:
        return False
    for f in _UPDATE_DIFF_UNCLEARABLE_FIELDS:
        if f in payload and payload[f] != vega_state.get(f):
            return False
    if not frequency_equal(
        payload.get("frequencyCron", ""), vega_state.get("frequencyCron")
    ):
        return False
    if not _cells_equal(payload.get("cells") or [], vega_state.get("cells")):
        return False
    return True


def build_plan(
    yaml_detections: list[dict[str, Any]],
    vega_detections: list[dict[str, Any]],
    unknown_library_ids: frozenset[str] = frozenset(),
) -> DetectionPlan:
    vega_by_external_id = {
        d["externalId"]: d for d in vega_detections if d.get("externalId")
    }
    yaml_by_id = {str(d["id"]).strip(): d for d in yaml_detections}

    plan = DetectionPlan()

    for ext_id, ydet in yaml_by_id.items():
        vdet = vega_by_external_id.get(ext_id)
        if is_library_file(ydet):
            _plan_library(plan, ydet, vdet, unknown_library_ids)
            continue
        if vdet is not None and is_library(vdet):
            # An update would turn Vega's detection into a custom copy that no
            # longer gets library updates, so the file has to say it is one.
            plan.blocked.append(
                Blocked(
                    "update",
                    ext_id,
                    str(ydet.get("name") or ext_id),
                    "this id is a Vega library detection in the tenant. Write "
                    "the file as a library detection (id, name, library: true, "
                    "state); the next pull does it for you",
                )
            )
            continue
        if vdet is not None:
            update_payload = yaml_to_update_input(ydet)
            if is_no_op_update(update_payload, vdet):
                plan.no_op_updates += 1
                continue
            plan.updates.append(_planned(update_payload))
        else:
            plan.creates.append(_planned(yaml_to_create_input(ydet)))

    for ext_id, vdet in vega_by_external_id.items():
        if ext_id in yaml_by_id:
            continue
        # A library detection is removed only when this repository added or
        # adopted it, which the label records. Repositories from before
        # library files existed therefore never remove one.
        if is_library(vdet) and not _has_managed_label(vdet):
            continue
        plan.deletes.append(
            Planned(ext_id, vdet.get("name") or "<unknown>", vdet["id"])
        )

    return plan


def _plan_library(
    plan: DetectionPlan,
    ydet: dict[str, Any],
    vdet: dict[str, Any] | None,
    unknown_library_ids: frozenset[str],
) -> None:
    payload = library_state_input(ydet)
    ext_id, name = payload["libraryDetectionId"], payload["name"]
    entry: Write = Planned(ext_id, name, payload)
    if vdet is None:
        if ext_id in unknown_library_ids:
            plan.blocked.append(
                Blocked(
                    "add",
                    ext_id,
                    name,
                    "no Vega library detection has this id. Copy the id from "
                    "the library in the Vega UI or from listLibraryDetections",
                )
            )
        else:
            plan.library_adds.append(entry)
    elif not is_library(vdet):
        plan.blocked.append(
            Blocked(
                "set_state",
                ext_id,
                name,
                "the tenant detection with this id is no longer connected to "
                "the Vega library (it was detached in the UI). Remove "
                "'library: true' and give the file the detection's fields; "
                "the next pull does it for you",
            )
        )
    elif vdet.get("state") == payload["state"]:
        plan.no_op_updates += 1
    else:
        plan.library_states.append(entry)


def _has_managed_label(vega_detection: dict[str, Any]) -> bool:
    return any(
        is_managed_label(lbl.get("name") or "")
        for lbl in vega_detection.get("labels") or []
    )


def is_library(vega_detection: dict[str, Any]) -> bool:
    created_by = vega_detection.get("createdBy") or {}
    return created_by.get("principalType") == "vega_library"


def _format_errors(errors: list[dict[str, Any]]) -> str:
    if not errors:
        return "validation failed (no error detail)"
    return "; ".join(f"{e.get('field') or '_'}: {e['message']}" for e in errors)


def _apply_batched(
    kind: ActionKind,
    entries: list[Write],
    api_call: Callable[[list[dict[str, Any]]], dict[str, Any]],
    report: SyncReport,
) -> None:
    for entries_batch in chunks(entries, BATCH_SIZE):
        batch = [e.payload for e in entries_batch]
        try:
            response = api_call(batch)
        except (VegaAPIError, RuntimeError) as e:
            # Prefix marks the failure as a whole-batch transport/API problem,
            # not per-detection validation. Helps readers of the report
            # distinguish "API was down" from "100 rules are broken".
            err = f"batch API error: {e}"
            for p in batch:
                report.add(
                    ActionResult(kind, p["externalId"], p["name"], False, err)
                )
            continue
        # The API returns one result per requested detection, in request order.
        # Match by position rather than by name: names are not unique across a
        # batch, and an update result echoes back only the name that was sent.
        # Fall back to name matching only if the counts somehow diverge.
        results = response.get("results", [])
        if len(results) == len(batch):
            matched = list(zip(batch, results))
        else:
            by_name = {r.get("name"): r for r in results}
            matched = [(p, by_name.get(p["name"])) for p in batch]

        # Each call is a single transaction: unless the whole batch validates,
        # nothing is written. Reporting the valid entries as applied would be a
        # lie, so a rolled-back batch marks them as blocked and points at the
        # detections that caused it. `committed` is non-nullable in the schema,
        # so treat its absence as "assume nothing landed" and say so - a
        # spurious re-run is cheap and idempotent, silent data loss is not.
        summary = response.get("summary") or {}
        committed = bool(summary.get("committed"))
        rejected = [
            p["externalId"]
            for p, res in matched
            if not (res and res.get("status") == "VALID")
        ]
        if "committed" not in summary:
            rollback_note = (
                "outcome unknown: the API response carried no commit status, "
                "so this detection may or may not have been written. Re-run "
                "the sync to confirm"
            )
        else:
            rollback_note = (
                f"rolled back: not applied because {len(rejected)} other "
                f"detection(s) in the same batch failed validation "
                f"({', '.join(rejected[:5])}"
                f"{', ...' if len(rejected) > 5 else ''})"
            )

        for p, res in matched:
            if res and res.get("status") == "VALID":
                report.add(
                    ActionResult(
                        kind,
                        p["externalId"],
                        p["name"],
                        committed,
                        None if committed else rollback_note,
                        object_id=(res.get("detection") or {}).get("id"),
                    )
                )
            else:
                err = (
                    _format_errors(res.get("errors") or [])
                    if res
                    else f"missing result for {p['name']!r}"
                )
                report.add(
                    ActionResult(kind, p["externalId"], p["name"], False, err)
                )


def _apply_library(
    client: VegaClient, plan: DetectionPlan, report: SyncReport
) -> None:
    adds = {e.external_id for e in plan.library_adds}
    by_state: dict[str, list[Write]] = {}
    for entry in [*plan.library_adds, *plan.library_states]:
        by_state.setdefault(entry.payload["state"], []).append(entry)

    for state, entries in by_state.items():
        for batch in chunks(entries, BATCH_SIZE):
            ids = [e.external_id for e in batch]
            try:
                response = client.set_library_detections_state(ids, state)
            except (VegaAPIError, RuntimeError) as e:
                for entry in batch:
                    kind: ActionKind = "add" if entry.external_id in adds else "set_state"
                    report.add(
                        ActionResult(
                            kind, entry.external_id, entry.name, False,
                            f"batch API error: {e}",
                        )
                    )
                continue
            results = {
                r.get("libraryDetectionId"): r for r in response.get("results") or []
            }
            errors: dict[int, dict[str, Any]] = {}
            for err in response.get("userErrors") or []:
                path = err.get("path") or []
                if path and str(path[-1]).isdigit():
                    errors[int(path[-1])] = err
            for i, entry in enumerate(batch):
                kind = "add" if entry.external_id in adds else "set_state"
                res = results.get(entry.external_id) or {}
                if res.get("status") in ("ADDED", "UPDATED", "UNCHANGED"):
                    report.add(
                        ActionResult(
                            kind, entry.external_id, entry.name, True,
                            object_id=(res.get("detection") or {}).get("id"),
                        )
                    )
                    continue
                err = errors.get(i)
                message = (
                    f"{err.get('code')}: {err.get('message')}"
                    if err
                    else f"library detection not set to {state} "
                    f"(status {res.get('status') or 'missing'})"
                )
                report.add(
                    ActionResult(kind, entry.external_id, entry.name, False, message)
                )


def execute_plan(
    client: VegaClient, plan: DetectionPlan, skip_deletes: bool = False
) -> SyncReport:
    report = SyncReport()
    _apply_batched("create", plan.creates, client.create_detections, report)
    _apply_batched("update", plan.updates, client.update_detections, report)
    _apply_library(client, plan, report)

    if not skip_deletes:
        for entry in plan.deletes:
            try:
                client.delete_detection(entry.payload)
                report.add(
                    ActionResult("delete", entry.external_id, entry.name, True)
                )
            except (VegaAPIError, RuntimeError) as e:
                report.add(
                    ActionResult(
                        "delete", entry.external_id, entry.name, False, str(e)
                    )
                )

    return report


def unlabelled_detections(
    vega_detections: list[dict[str, Any]], managed_ids: set[str]
) -> list[dict[str, Any]]:
    return [
        d
        for d in vega_detections
        if d.get("externalId") in managed_ids
        and not _has_managed_label(d)
    ]


def label_managed_detections(
    managed_ids: set[str],
    vega_detections: list[dict[str, Any]],
    report: SyncReport,
    client: VegaClient,
    label: ManagedLabel,
) -> None:
    missing = unlabelled_detections(vega_detections, managed_ids)
    targets = {d["id"]: (d["externalId"], d.get("name") or d["externalId"]) for d in missing}
    targets |= {
        r.object_id: (r.external_id, r.name)
        for r in report.results
        if r.success and r.kind in ("create", "add") and r.object_id
    }
    if not targets:
        return
    try:
        label_id = label.id()
    except (VegaAPIError, RuntimeError) as e:
        report.errors.append(
            f"detections: could not add the '{MANAGED_LABEL}' label: {e}"
        )
        return

    for batch in chunks(list(targets.items()), MODIFY_LABELS_MAX):
        try:
            client.attach_detection_labels([i for i, _ in batch], [label_id])
            error = None
        except (VegaAPIError, RuntimeError) as e:
            error = f"could not add the '{MANAGED_LABEL}' label: {e}"
        for _, (external_id, name) in batch:
            report.add(ActionResult("label", external_id, name, error is None, error))
