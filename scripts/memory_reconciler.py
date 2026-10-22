"""Declarative reconciler for memories: make Vega match the memories/ directory.

Each run:
1. Load every YAML in memories/.
2. Fetch every memory and every label. The memories that carry the managed
   label are the ones this sync owns; the ones people write in the UI and the
   ones Vega learns are never changed.
3. Match by title: create / update / delete. A file whose title belongs to a
   memory without the label is blocked rather than created a second time.
4. Skip no-op updates by comparing each file to its memory.
5. Apply deletes first, then updates, then creates. The tenant has a cap on
   active memories, so freeing room before adding keeps a rename (delete +
   create) or a swap from failing at the cap. The API has no batch calls, so
   each memory is its own request and a failure never blocks another one.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable

import yaml

from .client import (
    ACCESS_DENIED,
    LABELS_LABEL_NOT_FOUND,
    MEMORY_LIMIT_REACHED,
    VegaAPIError,
    VegaClient,
)
from .consts import (
    MANAGED_MEMORY_LABEL,
    MANAGED_MEMORY_LABEL_COLOR,
    MemoryStatus,
)
from .memory_translator import (
    MemorySpec,
    parse_memory,
    parse_time,
    to_create_input,
    to_update_input,
)
from .plan import ActionKind, ActionResult, Blocked, Plan, Planned, SyncReport
from .utils import yaml_files

_ERROR_HINTS: dict[str, str] = {
    MEMORY_LIMIT_REACHED: (
        "the tenant would pass its cap on active memories, which also counts "
        "the memories written in the UI and learned by Vega"
    ),
    LABELS_LABEL_NOT_FOUND: (
        "a label in the file was deleted from the tenant during the run; "
        "re-run the sync"
    ),
}


class MemoriesUnavailable(RuntimeError):
    pass


@dataclass
class MemoryPlan(Plan):
    managed_label_id: str | None = None


def load_yaml_memories(memories_dirs: Iterable[Path]) -> list[MemorySpec]:
    specs: list[MemorySpec] = []
    seen_titles: dict[str, Path] = {}
    for d in memories_dirs:
        for f in yaml_files(d):
            with open(f, "r", encoding="utf-8") as fh:
                doc = yaml.safe_load(fh)
            if doc is None:
                continue
            spec = parse_memory(doc, str(f))
            if spec.title in seen_titles:
                raise ValueError(
                    f"{f}: duplicate title {spec.title!r} (also in "
                    f"{seen_titles[spec.title]}). The title is what links a "
                    f"file to its memory, so it must be unique"
                )
            seen_titles[spec.title] = f
            specs.append(spec)
    return specs


def find_managed_label_id(labels: list[dict[str, Any]]) -> str | None:
    for label in labels:
        if (label.get("name") or "").strip().lower() == MANAGED_MEMORY_LABEL:
            return label["id"]
    return None


def _entity_key(etype: str, value: str) -> tuple[str, str]:
    return etype.upper(), value.strip().lower()


def _spec_entities(spec: MemorySpec) -> set[tuple[str, str]]:
    return {_entity_key(etype, value) for etype, value in spec.entities}


def _vega_entities(vega: dict[str, Any]) -> set[tuple[str, str]]:
    return {
        _entity_key(str(e["type"]), str(e["value"]))
        for e in vega.get("entities") or []
    }


def _is_no_op(
    spec: MemorySpec, vega: dict[str, Any], label_ids: list[str]
) -> bool:
    if spec.description != (vega.get("description") or "").strip():
        return False
    if spec.content != (vega.get("content") or "").strip():
        return False
    # `status` reads EXPIRED once the expiration passes, whatever the switch
    # says, so the switch itself is what the file is compared with.
    if (spec.status == MemoryStatus.ENABLED) != bool(vega.get("enabled")):
        return False
    if spec.expires_at != parse_time(vega.get("expiresAt"), spec.title):
        return False
    if _spec_entities(spec) != _vega_entities(vega):
        return False
    vega_label_ids = {label["id"] for label in vega.get("labels") or []}
    return set(label_ids) == vega_label_ids


def _has_label(vega: dict[str, Any], label_id: str | None) -> bool:
    return label_id is not None and any(
        label["id"] == label_id for label in vega.get("labels") or []
    )


def _title(vega: dict[str, Any]) -> str:
    return (vega.get("title") or "").strip()


def build_memory_plan(
    specs: list[MemorySpec],
    vega_memories: list[dict[str, Any]],
    labels: list[dict[str, Any]],
) -> MemoryPlan:
    label_ids_by_name = {
        (label.get("name") or "").strip().lower(): label["id"] for label in labels
    }
    plan = MemoryPlan(managed_label_id=find_managed_label_id(labels))

    managed_by_title: dict[str, dict[str, Any]] = {}
    unmanaged_by_title: dict[str, dict[str, Any]] = {}
    for vmem in vega_memories:
        title = _title(vmem)
        if not _has_label(vmem, plan.managed_label_id):
            unmanaged_by_title.setdefault(title, vmem)
        # Two managed memories with one title can only come from an edit in
        # the UI. getMemories is asked for the most recently changed first,
        # so that one is kept and the rest are cleaned up as stale.
        elif title in managed_by_title:
            plan.deletes.append(_delete_entry(vmem))
        else:
            managed_by_title[title] = vmem

    titles = {spec.title for spec in specs}
    for spec in specs:
        current = managed_by_title.get(spec.title)
        kind: ActionKind = "create" if current is None else "update"
        user_label_ids = [label_ids_by_name.get(n.lower()) for n in spec.labels]
        missing = [n for n, lid in zip(spec.labels, user_label_ids) if lid is None]
        released = unmanaged_by_title.get(spec.title)
        if missing:
            plan.blocked.append(
                Blocked(
                    kind,
                    (current or {}).get("vegaMemoryId") or "",
                    spec.title,
                    f"label(s) not found in the tenant: {', '.join(missing)}. "
                    f"Create them in Vega first, or remove them from the file",
                )
            )
        elif current is None and released is not None:
            plan.blocked.append(
                Blocked(
                    kind,
                    released.get("vegaMemoryId") or "",
                    spec.title,
                    f"a memory with this title already exists without the "
                    f"'{MANAGED_MEMORY_LABEL}' label, so creating it would "
                    f"duplicate it. Add the label to that memory in the Vega "
                    f"UI to hand it back to the sync, or delete it",
                )
            )
        elif current is None:
            plan.creates.append(
                Planned("", spec.title, to_create_input(spec, user_label_ids))
            )
        else:
            label_ids = [*user_label_ids, plan.managed_label_id]
            if _is_no_op(spec, current, label_ids):
                plan.no_op_updates += 1
            else:
                plan.updates.append(
                    Planned(
                        current.get("vegaMemoryId") or "",
                        spec.title,
                        to_update_input(spec, current["id"], label_ids),
                    )
                )

    for title, vmem in managed_by_title.items():
        if title not in titles:
            plan.deletes.append(_delete_entry(vmem))
    return plan


def _delete_entry(vmem: dict[str, Any]) -> Planned:
    return Planned(
        vmem.get("vegaMemoryId") or "", _title(vmem) or "<unknown>", vmem["id"]
    )


def fetch_memory_state(
    client: VegaClient,
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    try:
        memories = client.get_memories()
        labels = client.list_labels()
    except VegaAPIError as e:
        if ACCESS_DENIED in e.codes:
            raise MemoriesUnavailable(
                "memories are not available to this access key: either "
                "memories are not enabled for your organization, or the key "
                "lacks the AgentsRead or LabelsRead permission"
            ) from e
        raise
    return labels, memories


def _error_text(e: VegaAPIError) -> str:
    hints = [_ERROR_HINTS[c] for c in sorted(e.codes) if c in _ERROR_HINTS]
    return "; ".join([str(e), *hints])


def _result(
    kind: ActionKind, external_id: str, name: str, error: str | None = None
) -> ActionResult:
    return ActionResult(
        kind, external_id, name, error is None, error, target="memory"
    )


def _ensure_managed_label(
    client: VegaClient, plan: MemoryPlan, report: SyncReport
) -> bool:
    if plan.managed_label_id:
        return True
    try:
        label = client.create_label(
            MANAGED_MEMORY_LABEL, MANAGED_MEMORY_LABEL_COLOR
        )
    except VegaAPIError as e:
        reason = f"could not create the '{MANAGED_MEMORY_LABEL}' label: {e}"
        if ACCESS_DENIED in e.codes:
            reason += ". Creating it needs the LabelsWrite permission"
        for entry in plan.creates:
            report.add(_result("create", "", entry.name, reason))
        return False
    plan.managed_label_id = label["id"]
    return True


def execute_memory_plan(
    client: VegaClient,
    plan: MemoryPlan,
    dry_run: bool = False,
    skip_deletes: bool = False,
) -> SyncReport:
    report = SyncReport()
    if dry_run:
        return report

    report.add_blocked(plan, "memory")

    if not skip_deletes:
        for entry in plan.deletes:
            try:
                client.delete_memory(entry.payload)
                report.add(_result("delete", entry.external_id, entry.name))
            except VegaAPIError as e:
                report.add(
                    _result(
                        "delete", entry.external_id, entry.name, _error_text(e)
                    )
                )

    for entry in plan.updates:
        try:
            client.update_memory(entry.payload)
            report.add(_result("update", entry.external_id, entry.name))
        except VegaAPIError as e:
            report.add(
                _result("update", entry.external_id, entry.name, _error_text(e))
            )

    if plan.creates and _ensure_managed_label(client, plan, report):
        for entry in plan.creates:
            payload = {
                **entry.payload,
                "labelIds": [*entry.payload["labelIds"], plan.managed_label_id],
            }
            try:
                created = client.create_memory(payload)
                report.add(
                    _result(
                        "create", created.get("vegaMemoryId") or "", entry.name
                    )
                )
            except VegaAPIError as e:
                report.add(_result("create", "", entry.name, _error_text(e)))

    return report
