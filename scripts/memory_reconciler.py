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

from dataclasses import dataclass, field, replace
from pathlib import Path
from typing import Any, Callable, Iterable

import yaml

from .client import ACCESS_DENIED, VegaAPIError, VegaClient
from .consts import (
    MANAGED_MEMORY_LABEL,
    MANAGED_MEMORY_LABEL_COLOR,
    MemoryStatus,
)
from .labels import label_ids_by_name, label_key
from .memory_translator import (
    MemorySpec,
    parse_memory,
    to_create_input,
    to_update_input,
)
from .plan import (
    ActionKind,
    ActionResult,
    Blocked,
    Delete,
    Plan,
    Planned,
    SyncReport,
)
from .utils import UniqueKey, load_unique, parse_time, yaml_files


class MemoriesUnavailable(RuntimeError):
    pass


@dataclass
class MemoryPlan(Plan):
    managed_label_id: str | None = None


@dataclass(frozen=True)
class MemoryState:
    memories: list[dict[str, Any]]
    labels: list[dict[str, Any]]


@dataclass
class _TenantMemories:
    managed: dict[str, dict[str, Any]] = field(default_factory=dict)
    unmanaged: dict[str, dict[str, Any]] = field(default_factory=dict)
    stale: list[dict[str, Any]] = field(default_factory=list)


def _load_memory_file(path: Path) -> MemorySpec | None:
    with open(path, "r", encoding="utf-8") as fh:
        doc = yaml.safe_load(fh)
    return None if doc is None else parse_memory(doc, str(path))


def load_yaml_memories(memories_dirs: Iterable[Path]) -> list[MemorySpec]:
    return load_unique(
        (f for d in memories_dirs for f in yaml_files(d)),
        _load_memory_file,
        [
            UniqueKey(
                "title",
                lambda spec: spec.title,
                "The title is what links a file to its memory, so it must "
                "be unique",
            )
        ],
    )


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
    vega_expires_at = parse_time(vega.get("expiresAt"), spec.title, "expiresAt")
    if spec.expires_at != vega_expires_at:
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


def _index_by_title(
    vega_memories: list[dict[str, Any]], managed_label_id: str | None
) -> _TenantMemories:
    tenant = _TenantMemories()
    for vmem in vega_memories:
        title = _title(vmem)
        if not _has_label(vmem, managed_label_id):
            tenant.unmanaged.setdefault(title, vmem)
        # Two managed memories with one title can only come from an edit in
        # the UI. getMemories is asked for the most recently changed first,
        # so that one is kept and the rest are cleaned up as stale.
        elif title in tenant.managed:
            tenant.stale.append(vmem)
        else:
            tenant.managed[title] = vmem
    return tenant


def _released_reason(managed_label_id: str | None) -> str:
    duplicate = (
        f"a memory with this title already exists without the "
        f"'{MANAGED_MEMORY_LABEL}' label, so creating it would duplicate it"
    )
    if managed_label_id is None:
        return (
            f"{duplicate}. The label does not exist yet: create "
            f"'{MANAGED_MEMORY_LABEL}' in the Vega UI and add it to that "
            f"memory to hand it to the sync, or delete the memory"
        )
    return (
        f"{duplicate}. Add the label to that memory in the Vega UI to hand it "
        f"back to the sync, or delete it"
    )


def _blocked(
    spec: MemorySpec,
    current: dict[str, Any] | None,
    released: dict[str, Any] | None,
    label_ids: dict[str, str],
    managed_label_id: str | None,
) -> Blocked | None:
    kind: ActionKind = "create" if current is None else "update"
    missing = [n for n in spec.labels if label_key(n) not in label_ids]
    if missing:
        return Blocked(
            kind,
            (current or {}).get("vegaMemoryId") or "",
            spec.title,
            f"label(s) not found in the tenant: {', '.join(missing)}. "
            f"Create them in Vega first, or remove them from the file",
        )
    if current is None and released is not None:
        return Blocked(
            kind,
            released.get("vegaMemoryId") or "",
            spec.title,
            _released_reason(managed_label_id),
        )
    return None


def _plan_memory(
    plan: MemoryPlan,
    spec: MemorySpec,
    tenant: _TenantMemories,
    label_ids: dict[str, str],
) -> None:
    current = tenant.managed.get(spec.title)
    blocked = _blocked(
        spec,
        current,
        tenant.unmanaged.get(spec.title),
        label_ids,
        plan.managed_label_id,
    )
    if blocked is not None:
        plan.blocked.append(blocked)
        return
    # On the first run the managed label does not exist yet, and only
    # creates can be planned; _ensure_managed_label adds it to them.
    ids = [label_ids[label_key(n)] for n in spec.labels]
    if plan.managed_label_id is not None:
        ids.append(plan.managed_label_id)
    if current is None:
        plan.creates.append(Planned("", spec.title, to_create_input(spec, ids)))
    elif _is_no_op(spec, current, ids):
        plan.no_op_updates += 1
    else:
        plan.updates.append(
            Planned(
                current.get("vegaMemoryId") or "",
                spec.title,
                to_update_input(spec, current["id"], ids),
            )
        )


def build_memory_plan(
    specs: list[MemorySpec],
    vega_memories: list[dict[str, Any]],
    labels: list[dict[str, Any]],
) -> MemoryPlan:
    label_ids = label_ids_by_name(labels)
    plan = MemoryPlan(managed_label_id=label_ids.get(MANAGED_MEMORY_LABEL))
    tenant = _index_by_title(vega_memories, plan.managed_label_id)
    for spec in specs:
        _plan_memory(plan, spec, tenant, label_ids)

    titles = {spec.title for spec in specs}
    leaving = [v for title, v in tenant.managed.items() if title not in titles]
    plan.deletes = [_delete_entry(v) for v in [*tenant.stale, *leaving]]
    return plan


def _delete_entry(vmem: dict[str, Any]) -> Delete:
    return Planned(
        vmem.get("vegaMemoryId") or "", _title(vmem) or "<unknown>", vmem["id"]
    )


def fetch_memory_state(client: VegaClient) -> MemoryState:
    try:
        return MemoryState(
            memories=client.get_memories(), labels=client.list_labels()
        )
    except VegaAPIError as e:
        if ACCESS_DENIED in e.codes:
            raise MemoriesUnavailable(
                "memories are not available to this access key: either "
                "memories are not enabled for your organization, or the key "
                "lacks the AgentsRead or LabelsRead permission"
            ) from e
        raise


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
        for entry in plan.creates:
            report.add(_result("create", "", entry.name, reason))
        return False
    plan.managed_label_id = label["id"]
    plan.creates = [
        replace(
            entry,
            payload={
                **entry.payload,
                "labelIds": [*entry.payload["labelIds"], label["id"]],
            },
        )
        for entry in plan.creates
    ]
    return True


def _apply(
    kind: ActionKind,
    entries: list[Planned[Any]],
    api_call: Callable[[Any], dict[str, Any]],
    report: SyncReport,
) -> None:
    for entry in entries:
        try:
            written = api_call(entry.payload)
        except VegaAPIError as e:
            report.add(_result(kind, entry.external_id, entry.name, str(e)))
            continue
        external_id = entry.external_id or written.get("vegaMemoryId") or ""
        report.add(_result(kind, external_id, entry.name))


def execute_memory_plan(
    client: VegaClient, plan: MemoryPlan, skip_deletes: bool = False
) -> SyncReport:
    report = SyncReport()
    if not skip_deletes:
        _apply("delete", plan.deletes, client.delete_memory, report)
    _apply("update", plan.updates, client.update_memory, report)
    if plan.creates and _ensure_managed_label(client, plan, report):
        _apply("create", plan.creates, client.create_memory, report)
    return report
