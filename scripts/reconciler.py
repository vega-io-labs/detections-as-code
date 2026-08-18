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
from typing import Any, Callable, Iterable, Literal

import yaml

from .client import VegaAPIError, VegaClient
from .consts import DetectionState
from .translator import (
    frequency_interval_seconds,
    yaml_state,
    yaml_to_create_input,
    yaml_to_update_input,
)
from .utils import chunks

ActionKind = Literal["create", "update", "delete", "set_state"]

BATCH_SIZE = 100  # createDetections / updateDetections cap per call


@dataclass
class Plan:
    creates: list[dict[str, Any]] = field(default_factory=list)
    updates: list[dict[str, Any]] = field(default_factory=list)
    deletes: list[dict[str, Any]] = field(default_factory=list)
    create_state_overrides: dict[str, DetectionState] = field(
        default_factory=dict
    )
    no_op_updates: int = 0

    def summary(self) -> str:
        return (
            f"creates={len(self.creates)} "
            f"updates={len(self.updates)} "
            f"deletes={len(self.deletes)} "
            f"no_op_skipped={self.no_op_updates}"
        )


@dataclass
class ActionResult:
    kind: ActionKind
    external_id: str
    name: str
    success: bool
    error: str | None = None


@dataclass
class SyncReport:
    results: list[ActionResult] = field(default_factory=list)

    def add(self, r: ActionResult) -> None:
        self.results.append(r)

    @property
    def succeeded(self) -> list[ActionResult]:
        return [r for r in self.results if r.success]

    @property
    def failed(self) -> list[ActionResult]:
        return [r for r in self.results if not r.success]

    @property
    def all_ok(self) -> bool:
        return not self.failed


def load_yaml_detections(detections_dirs: Iterable[Path]) -> list[dict[str, Any]]:
    detections: list[dict[str, Any]] = []
    seen_ids: dict[str, Path] = {}
    for d in detections_dirs:
        if not d.exists():
            raise FileNotFoundError(f"detections dir not found: {d}")
        files = sorted(list(d.glob("**/*.yaml")) + list(d.glob("**/*.yml")))
        for f in files:
            with open(f, "r", encoding="utf-8") as fh:
                doc = yaml.safe_load(fh)
            if doc is None:
                continue
            if "id" not in doc:
                raise ValueError(f"{f}: YAML missing required 'id'")
            ext_id = str(doc["id"])
            if ext_id in seen_ids:
                raise ValueError(
                    f"{f}: duplicate id {ext_id!r} (also in {seen_ids[ext_id]})"
                )
            seen_ids[ext_id] = f
            detections.append(doc)
    return detections


# Fields that meaningfully describe a detection. If all of these match between
# the YAML payload and the current Vega state, the update is a no-op.
_UPDATE_DIFF_FIELDS = (
    "name",
    "severity",
    "state",
    "lookBackSeconds",
    "mitreTechniques",
    "logicDescription",
    "attackScenario",
    "references",
    "deduplicationFields",
)

# actorFields/targetFields are priority-ordered, so reordering is a real change
# and they must not go through the order-insensitive list compare above.
_UPDATE_DIFF_ORDERED_FIELDS = (
    "actorFields",
    "targetFields",
)

# Neither can be cleared through the API: an omitted value and an explicit null
# are indistinguishable to the server, so it reads both as "leave unchanged".
# They are therefore only compared when the YAML actually sets them - otherwise
# a detection that once had a grouping field would report a diff on every run
# and never converge.
_UPDATE_DIFF_UNCLEARABLE_FIELDS = (
    "groupingField",
    "groupingThreshold",
)


def _frequency_equal(yaml_value: str, vega_value: str | None) -> bool:
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


def _normalise_cell_query(query: str | None) -> str:
    return _CELL_REFERENCE_RE.sub("@", (query or "").strip())


def _cells_equal(yaml_cells: list, vega_cells: list | None) -> bool:
    if vega_cells is None:
        return False
    if len(yaml_cells) != len(vega_cells):
        return False
    yk = sorted(yaml_cells, key=lambda c: c.get("name") or "")
    vk = sorted(vega_cells, key=lambda c: c.get("name") or "")
    for a, b in zip(yk, vk):
        if a.get("name") != b.get("name"):
            return False
        if _normalise_cell_query(a.get("query")) != _normalise_cell_query(
            b.get("query")
        ):
            return False
        if bool(a.get("trigger")) != bool(b.get("trigger")):
            return False
    return True


def _is_no_op_update(
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
    # Vega reports a disabled window as either null or 0.
    if (payload.get("deduplicationWindowSeconds") or 0) != (
        vega_state.get("deduplicationWindowSeconds") or 0
    ):
        return False
    for f in _UPDATE_DIFF_UNCLEARABLE_FIELDS:
        if f in payload and payload[f] != vega_state.get(f):
            return False
    if not _frequency_equal(
        payload.get("frequencyCron", ""), vega_state.get("frequencyCron")
    ):
        return False
    if not _cells_equal(payload.get("cells") or [], vega_state.get("cells")):
        return False
    return True


def build_plan(
    yaml_detections: list[dict[str, Any]],
    vega_detections: list[dict[str, Any]],
) -> Plan:
    vega_by_external_id = {
        d["externalId"]: d for d in vega_detections if d.get("externalId")
    }
    yaml_by_id = {str(d["id"]): d for d in yaml_detections}

    plan = Plan()

    for ext_id, ydet in yaml_by_id.items():
        if ext_id in vega_by_external_id:
            update_payload = yaml_to_update_input(ydet)
            if _is_no_op_update(update_payload, vega_by_external_id[ext_id]):
                plan.no_op_updates += 1
                continue
            plan.updates.append(update_payload)
        else:
            plan.creates.append(yaml_to_create_input(ydet))
            desired_state = yaml_state(ydet)
            if desired_state != DetectionState.ENABLED:
                plan.create_state_overrides[ext_id] = desired_state

    for ext_id, vdet in vega_by_external_id.items():
        if ext_id not in yaml_by_id:
            plan.deletes.append(vdet)

    return plan


def _format_errors(errors: list[dict[str, Any]]) -> str:
    if not errors:
        return "validation failed (no error detail)"
    return "; ".join(f"{e.get('field') or '_'}: {e['message']}" for e in errors)


def _apply_batched(
    kind: ActionKind,
    payloads: list[dict[str, Any]],
    api_call: Callable[[list[dict[str, Any]]], dict[str, Any]],
    report: SyncReport,
) -> None:
    for batch in chunks(payloads, BATCH_SIZE):
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


def _apply_state_overrides(
    client: VegaClient, plan: Plan, report: SyncReport
) -> None:
    if not plan.create_state_overrides:
        return
    try:
        vega_now = {d["externalId"]: d for d in client.get_detections()}
    except (VegaAPIError, RuntimeError) as e:
        for ext_id in plan.create_state_overrides:
            report.add(
                ActionResult(
                    "set_state",
                    ext_id,
                    "<unknown>",
                    False,
                    f"could not refetch detections: {e}",
                )
            )
        return

    # Group by target state so each unique state needs only chunked calls,
    # not one call per detection. Each triple is (system_id, external_id, name).
    by_state: dict[DetectionState, list[tuple[str, str, str]]] = {}
    for ext_id, state in plan.create_state_overrides.items():
        d = vega_now.get(ext_id)
        if not d or not d.get("id"):
            report.add(
                ActionResult(
                    "set_state",
                    ext_id,
                    "<unknown>",
                    False,
                    "detection not found after create",
                )
            )
            continue
        by_state.setdefault(state, []).append(
            (d["id"], ext_id, d.get("name") or ext_id)
        )

    for state, triples in by_state.items():
        for batch in chunks(triples, BATCH_SIZE):
            ids = [t[0] for t in batch]
            try:
                client.set_detections_state(ids, state.value)
            except (VegaAPIError, RuntimeError) as e:
                err = f"batch API error: {e}"
                for _, ext_id, name in batch:
                    report.add(
                        ActionResult("set_state", ext_id, name, False, err)
                    )
                continue
            for _, ext_id, name in batch:
                report.add(ActionResult("set_state", ext_id, name, True))


def execute_plan(
    client: VegaClient,
    plan: Plan,
    dry_run: bool = False,
    skip_deletes: bool = False,
) -> SyncReport:
    report = SyncReport()
    if dry_run:
        return report

    _apply_batched("create", plan.creates, client.create_detections, report)
    _apply_state_overrides(client, plan, report)
    _apply_batched("update", plan.updates, client.update_detections, report)

    if plan.deletes and not skip_deletes:
        for vdet in plan.deletes:
            ext_id = vdet.get("externalId") or "<unknown>"
            name = vdet.get("name") or "<unknown>"
            try:
                client.delete_detection(vdet["id"])
                report.add(ActionResult("delete", ext_id, name, True))
            except (VegaAPIError, RuntimeError) as e:
                report.add(ActionResult("delete", ext_id, name, False, str(e)))

    return report
