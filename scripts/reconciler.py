"""Declarative reconciler: make Vega state match the YAML directory.

Each run, regardless of what changed in git:
1. Load every YAML in detections/.
2. Fetch every detection from Vega.
3. Classify by externalId: create / update / delete.
4. Skip no-op updates by comparing the desired payload to the current Vega state.
5. Apply creates and updates in chunks of BATCH_SIZE; the API returns a
   per-detection `results` array so we still report success/failure per rule.
   Deletes are single-shot (the API has no bulk delete).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Iterable, Literal

import yaml

from .client import VegaAPIError, VegaClient
from .consts import DetectionState
from .translator import yaml_state, yaml_to_create_input, yaml_to_update_input
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
    "groupingField",
)

# actorFields/targetFields are priority-ordered, so reordering is a real change
# and they must not go through the order-insensitive list compare above.
_UPDATE_DIFF_ORDERED_FIELDS = (
    "actorFields",
    "targetFields",
)


def _frequency_equal(yaml_value: str, vega_value: str | None) -> bool:
    # Vega normalises fixed intervals server-side (`60m` can read back as
    # `@every 60m` or `FIXED_INTERVAL 60m`). Compare loosely, else every run
    # sees a phantom diff and pushes a new detection version.
    if vega_value is None:
        return False

    def _norm(value: str) -> str:
        v = (value or "").strip().lower()
        for prefix in ("@every ", "fixed_interval "):
            v = v.removeprefix(prefix)
        return v

    return _norm(yaml_value) == _norm(vega_value)


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
        if (a.get("query") or "").strip() != (b.get("query") or "").strip():
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
    # groupingThreshold only matters while a groupingField is set; without one
    # Vega still reports its default threshold, which is not a real diff.
    if payload.get("groupingField") is not None and payload.get(
        "groupingThreshold"
    ) != vega_state.get("groupingThreshold"):
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
        # updateDetections returns results with an empty `name`, so results
        # can only be matched back to the request by position. The API keeps
        # request order; fall back to name matching if the counts diverge.
        results = response.get("results", [])
        if len(results) == len(batch):
            matched = list(zip(batch, results))
        else:
            by_name = {r.get("name"): r for r in results}
            matched = [(p, by_name.get(p["name"])) for p in batch]
        for p, res in matched:
            if res and res.get("status") == "VALID":
                report.add(ActionResult(kind, p["externalId"], p["name"], True))
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
