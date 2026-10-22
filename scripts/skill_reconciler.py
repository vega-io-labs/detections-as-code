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

from .client import ACCESS_DENIED, VegaAPIError, VegaClient
from .consts import SKILL_FILE_NAME
from .plan import ActionKind, ActionResult, Blocked, Plan, Planned, SyncReport
from .reconciler import DetectionPlan
from .skill_translator import (
    SkillSpec,
    parse_skill,
    to_create_input,
    to_update_input,
)
from .utils import chunks

BATCH_SIZE = 100  # createSkills / updateSkills / deleteSkills cap per call


def load_skill_files(skills_dirs: Iterable[Path]) -> list[SkillSpec]:
    specs: list[SkillSpec] = []
    seen_ids: dict[str, str] = {}
    seen_names: dict[str, str] = {}
    for d in skills_dirs:
        for f in sorted(d.glob(f"**/{SKILL_FILE_NAME}")):
            spec = parse_skill(f.read_text(encoding="utf-8"), str(f))
            if spec.external_id in seen_ids:
                raise ValueError(
                    f"{f}: duplicate id {spec.external_id!r} (also in "
                    f"{seen_ids[spec.external_id]})"
                )
            if spec.name in seen_names:
                raise ValueError(
                    f"{f}: duplicate name {spec.name!r} (also in "
                    f"{seen_names[spec.name]}). createSkills matches an "
                    f"existing skill by name, so the two files would end up "
                    f"as one skill"
                )
            seen_ids[spec.external_id] = str(f)
            seen_names[spec.name] = str(f)
            specs.append(spec)
    return specs


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


def build_skill_plan(
    specs: list[SkillSpec], vega_skills: list[dict[str, Any]]
) -> Plan:
    plan = Plan()
    managed = {s["externalId"]: s for s in managed_skills(vega_skills)}

    repo_ids = {spec.external_id for spec in specs}
    leaving = [s for ext, s in managed.items() if ext not in repo_ids]
    plan.deletes = [
        Planned(s["externalId"], s.get("name") or "<unknown>", s["id"])
        for s in leaving
    ]
    leaving_ids = {s["id"] for s in leaving}

    holders_by_name: dict[str, list[dict[str, Any]]] = {}
    for s in vega_skills:
        if not s.get("readOnly") and s["id"] not in leaving_ids:
            holders_by_name.setdefault(s.get("name") or "", []).append(s)

    for spec in specs:
        current = managed.get(spec.external_id)
        others = [
            s
            for s in holders_by_name.get(spec.name, [])
            if current is None or s["id"] != current["id"]
        ]
        ui_holder = next((s for s in others if not s.get("externalId")), None)
        # Names are not unique on the server, so repo skills may swap names
        # in one run. Only a new file has to wait for the rename that frees
        # its name.
        renaming_repo_holder = (
            next((s for s in others if s.get("externalId")), None)
            if current is None
            else None
        )
        kind: ActionKind = "create" if current is None else "update"

        # createSkills falls back to matching by name, so a file named like a
        # skill it does not own would silently take that skill over.
        if ui_holder is not None:
            plan.blocked.append(
                Blocked(
                    kind,
                    spec.external_id,
                    spec.name,
                    f"the name {spec.name!r} is already used by a skill this "
                    f"repo does not manage (id {ui_holder['id']}). Syncing "
                    f"would overwrite it or duplicate the name, so rename one "
                    f"of them",
                )
            )
        elif renaming_repo_holder is not None:
            plan.blocked.append(
                Blocked(
                    kind,
                    spec.external_id,
                    spec.name,
                    f"the name {spec.name!r} still belongs to the skill with "
                    f"id {renaming_repo_holder['externalId']} in skills/, "
                    f"which this run renames. Merge the rename first, then "
                    f"add this skill",
                )
            )
        elif current is None:
            plan.creates.append(
                Planned(spec.external_id, spec.name, to_create_input(spec))
            )
        elif _is_no_op(spec, current):
            plan.no_op_updates += 1
        else:
            plan.updates.append(
                Planned(
                    spec.external_id,
                    spec.name,
                    to_update_input(spec, current["id"]),
                )
            )
    return plan


def _error_text(errors: list[dict[str, Any]]) -> str:
    if not errors:
        return "rejected (no error detail)"
    return "; ".join(
        f"{e.get('field') or e.get('code') or '_'}: {e.get('message')}"
        for e in errors
    )


def _batch_error(e: VegaAPIError) -> str:
    if ACCESS_DENIED in e.codes:
        return (
            f"batch API error: {e}. Managing skills needs the AgentsWrite "
            f"permission on the access key"
        )
    return f"batch API error: {e}"


def _apply(
    kind: ActionKind,
    entries: list[Planned],
    api_call: Callable[[list[Any]], dict[str, Any]],
    report: SyncReport,
) -> None:
    for batch in chunks(entries, BATCH_SIZE):
        try:
            results = api_call([e.payload for e in batch])["results"]
        except VegaAPIError as e:
            for entry in batch:
                report.add(
                    ActionResult(
                        kind,
                        entry.external_id,
                        entry.name,
                        False,
                        _batch_error(e),
                        target="skill",
                    )
                )
            continue
        # Results come back one per entry, in request order.
        for i, entry in enumerate(batch):
            res = results[i] if i < len(results) else None
            ok = bool(res) and res.get("status") == "VALID"
            error = None if ok else (
                _error_text(res.get("errors") or [])
                if res
                else f"missing result for {entry.name!r}"
            )
            report.add(
                ActionResult(
                    kind, entry.external_id, entry.name, ok, error, target="skill"
                )
            )


def execute_skill_plan(
    client: VegaClient,
    plan: Plan,
    dry_run: bool = False,
    skip_deletes: bool = False,
) -> SyncReport:
    report = SyncReport()
    if dry_run:
        return report

    report.add_blocked(plan, "skill")
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
    buckets: tuple[tuple[list[Planned], ActionKind], ...] = (
        (plan.creates, "create"),
        (plan.updates, "update"),
    )
    for bucket, kind in buckets:
        keep: list[Planned] = []
        for entry in bucket:
            missing = unresolved.get(entry.external_id.strip())
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
