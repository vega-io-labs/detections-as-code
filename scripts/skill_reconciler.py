"""Declarative reconciler for skills: make Vega match the skills/ directory.

Each run:
1. Load every SKILL.md under skills/.
2. Fetch the tenant's skills. Only skills the tenant owns that carry an
   externalId are managed: skills written in the UI have none, and Vega
   library skills are read-only.
3. Match by externalId (the file's `id`): create / update / delete.
4. Skip no-op updates by comparing each file to its skill.
5. Apply deletes first, then updates, then creates, in batches of 100. Each
   skill in a batch is applied on its own, so one rejected skill never blocks
   another.

Detections run after skills, so a detection can name a skill from this repo by
its `id` in `skillIds`; resolve_detection_skill_ids swaps in the tenant id.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any, Callable, Iterable

from .client import VegaAPIError, VegaClient
from .plan import (
    ActionKind,
    ActionResult,
    Blocked,
    Plan,
    Planned,
    SyncReport,
    Write,
)
from .reconciler import DetectionPlan
from .skill_translator import (
    SkillSpec,
    parse_skill,
    to_create_input,
    to_update_input,
)
from .utils import UniqueKey, chunks, load_unique, skill_files

BATCH_SIZE = 100  # createSkills / updateSkills / deleteSkills cap per call


def _load_skill_file(path: Path) -> SkillSpec:
    return parse_skill(path.read_text(encoding="utf-8"), str(path))


def load_skill_files(skills_dirs: Iterable[Path]) -> list[SkillSpec]:
    return load_unique(
        (f for d in skills_dirs for f in skill_files(d)),
        _load_skill_file,
        [
            UniqueKey("id", lambda spec: spec.external_id),
            UniqueKey(
                "name",
                lambda spec: spec.name,
                "createSkills matches an existing skill by name, so the two "
                "files would end up as one skill",
            ),
        ],
    )


def managed_skills(vega_skills: list[dict[str, Any]]) -> list[dict[str, Any]]:
    return [
        s for s in vega_skills if not s.get("readOnly") and s.get("externalId")
    ]


def _is_no_op(spec: SkillSpec, vega: dict[str, Any]) -> bool:
    return (
        spec.name == (vega.get("name") or "").strip()
        and spec.description == (vega.get("description") or "").strip()
        and spec.type.value == vega.get("type")
        and spec.instructions == (vega.get("instructions") or "").strip()
    )


def _name_holders(
    vega_skills: list[dict[str, Any]], leaving_ids: set[str]
) -> dict[str, list[dict[str, Any]]]:
    holders: dict[str, list[dict[str, Any]]] = {}
    for s in vega_skills:
        if not s.get("readOnly") and s["id"] not in leaving_ids:
            holders.setdefault(s.get("name") or "", []).append(s)
    return holders


def _blocked(
    spec: SkillSpec,
    current: dict[str, Any] | None,
    holders: list[dict[str, Any]],
) -> Blocked | None:
    kind: ActionKind = "create" if current is None else "update"
    others = [s for s in holders if current is None or s["id"] != current["id"]]
    # createSkills falls back to matching by name, so a file named like a
    # skill it does not own would silently take that skill over.
    ui_holder = next((s for s in others if not s.get("externalId")), None)
    if ui_holder is not None:
        return Blocked(
            kind,
            spec.external_id,
            spec.name,
            f"the name {spec.name!r} is already used by a skill this repo "
            f"does not manage (id {ui_holder['id']}). Syncing would overwrite "
            f"it or duplicate the name, so rename one of them",
        )
    # Names are not unique on the server, so repo skills may swap names in
    # one run. Only a new file has to wait for the rename that frees its name.
    repo_holder = next((s for s in others if s.get("externalId")), None)
    if current is None and repo_holder is not None:
        return Blocked(
            kind,
            spec.external_id,
            spec.name,
            f"the name {spec.name!r} still belongs to the skill with id "
            f"{repo_holder['externalId']} in skills/, which this run renames. "
            f"Merge the rename first, then add this skill",
        )
    return None


def _plan_skill(
    plan: Plan,
    spec: SkillSpec,
    current: dict[str, Any] | None,
    holders: list[dict[str, Any]],
) -> None:
    blocked = _blocked(spec, current, holders)
    if blocked is not None:
        plan.blocked.append(blocked)
    elif current is None:
        plan.creates.append(
            Planned(spec.external_id, spec.name, to_create_input(spec))
        )
    elif _is_no_op(spec, current):
        plan.no_op_updates += 1
    else:
        plan.updates.append(
            Planned(
                spec.external_id, spec.name, to_update_input(spec, current["id"])
            )
        )


def build_skill_plan(
    specs: list[SkillSpec], vega_skills: list[dict[str, Any]]
) -> Plan:
    managed = {s["externalId"]: s for s in managed_skills(vega_skills)}
    repo_ids = {spec.external_id for spec in specs}
    leaving = [s for ext, s in managed.items() if ext not in repo_ids]
    plan = Plan(
        deletes=[
            Planned(s["externalId"], s.get("name") or "<unknown>", s["id"])
            for s in leaving
        ]
    )
    holders = _name_holders(vega_skills, {s["id"] for s in leaving})
    for spec in specs:
        _plan_skill(
            plan, spec, managed.get(spec.external_id), holders.get(spec.name, [])
        )
    return plan


def _error_text(errors: list[dict[str, Any]]) -> str:
    if not errors:
        return "rejected (no error detail)"
    return "; ".join(
        f"{e.get('field') or e.get('code') or '_'}: {e.get('message')}"
        for e in errors
    )


def _result_error(entry: Planned[Any], res: dict[str, Any] | None) -> str | None:
    if not res:
        return f"missing result for {entry.name!r}"
    if res.get("status") == "VALID":
        return None
    return _error_text(res.get("errors") or [])


def _apply(
    kind: ActionKind,
    entries: list[Planned[Any]],
    api_call: Callable[[list[Any]], dict[str, Any]],
    report: SyncReport,
) -> None:
    for batch in chunks(entries, BATCH_SIZE):
        try:
            results = api_call([e.payload for e in batch])["results"]
        except VegaAPIError as e:
            errors = [f"batch API error: {e}"] * len(batch)
        else:
            # Results come back one per entry, in request order.
            errors = [
                _result_error(entry, results[i] if i < len(results) else None)
                for i, entry in enumerate(batch)
            ]
        for entry, error in zip(batch, errors):
            report.add(
                ActionResult(
                    kind,
                    entry.external_id,
                    entry.name,
                    error is None,
                    error,
                    target="skill",
                )
            )


def execute_skill_plan(
    client: VegaClient, plan: Plan, skip_deletes: bool = False
) -> SyncReport:
    report = SyncReport()
    if not skip_deletes:
        _apply("delete", plan.deletes, client.delete_skills, report)
    _apply("update", plan.updates, client.update_skills, report)
    _apply("create", plan.creates, client.create_skills, report)
    return report


def skill_ids_by_external_id(vega_skills: list[dict[str, Any]]) -> dict[str, str]:
    return {s["externalId"]: s["id"] for s in managed_skills(vega_skills)}


def resolve_detection_skill_ids(
    yaml_detections: list[dict[str, Any]],
    specs: list[SkillSpec],
    tenant_ids: dict[str, str],
) -> tuple[list[dict[str, Any]], dict[str, list[str]]]:
    """Swap repo skill ids in each detection's skillIds for tenant skill ids.

    A skill's tenant id is assigned by Vega, so a detection in the same repo
    can only know the skill by the `id` in its SKILL.md. Values that are not a
    repo skill id pass through untouched, so plain Vega skill ids keep working.
    Returns the resolved detections and, per detection id, the repo skills it
    names that are not in the tenant.
    """
    repo_ids = {spec.external_id for spec in specs}
    resolved: list[dict[str, Any]] = []
    unresolved: dict[str, list[str]] = {}
    for doc in yaml_detections:
        values = doc.get("skillIds")
        if not isinstance(values, list) or not any(
            str(v).strip() in repo_ids for v in values
        ):
            resolved.append(doc)
            continue
        out: list[str] = []
        for value in values:
            value = str(value).strip()
            if value in repo_ids:
                if value in tenant_ids:
                    value = tenant_ids[value]
                else:
                    unresolved.setdefault(str(doc.get("id")).strip(), []).append(value)
            if value not in out:
                out.append(value)
        resolved.append({**doc, "skillIds": out})
    return resolved, unresolved


def hold_back_detections(
    plan: DetectionPlan, unresolved: dict[str, list[str]]
) -> None:
    """Move detections whose repo skills did not sync to plan.blocked.

    Writing them anyway would either detach the skill or fail the whole
    createDetections / updateDetections batch, which is one transaction.
    Deletes are left alone: the detection still has its file.
    """
    buckets: tuple[tuple[list[Write], ActionKind], ...] = (
        (plan.creates, "create"),
        (plan.updates, "update"),
    )
    for bucket, kind in buckets:
        keep: list[Write] = []
        for entry in bucket:
            missing = unresolved.get(entry.external_id)
            if not missing:
                keep.append(entry)
                continue
            plan.create_state_overrides.pop(entry.external_id, None)
            plan.blocked.append(
                Blocked(
                    kind,
                    entry.external_id,
                    entry.name,
                    f"skillIds names skill(s) {', '.join(missing)} from "
                    f"skills/ that are not in the tenant; fix the skill "
                    f"errors in this run first",
                )
            )
        bucket[:] = keep
