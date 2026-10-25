from __future__ import annotations

from typing import Any

import pytest

from scripts.client import VegaAPIError
from scripts.memory_reconciler import (
    MemoriesUnavailable,
    build_memory_plan,
    execute_memory_plan,
    fetch_memory_state,
    load_yaml_memories,
)
from scripts.memory_translator import parse_memory

from .conftest import (
    LABELS,
    MANAGED_LABEL_ID,
    OTHER_LABEL_ID,
    make_memory_yaml,
    make_vega_memory,
)


def spec(**overrides: Any):
    return parse_memory(make_memory_yaml(**overrides), "f.yaml")


def test_identical_memory_is_a_no_op():
    plan = build_memory_plan([spec()], [make_vega_memory()], LABELS)
    assert plan.no_op_updates == 1
    assert not plan.creates and not plan.updates and not plan.deletes


def test_entity_case_and_order_do_not_diff():
    current = make_vega_memory(
        entities=[{"type": "IP", "value": "192.0.2.10"}, {"type": "DEVICE", "value": "SCANNER-01"}]
    )
    assert build_memory_plan([spec()], [current], LABELS).no_op_updates == 1


def test_expired_memory_with_the_switch_on_is_a_no_op():
    current = make_vega_memory(status="EXPIRED", enabled=True, expiresAt="2020-01-01T00:00:00Z")
    assert build_memory_plan([spec(expiresAt="2020-01-01")], [current], LABELS).no_op_updates == 1


@pytest.mark.parametrize(
    "overrides",
    [
        {"content": "changed"},
        {"description": "changed"},
        {"status": "disabled"},
        {"expiresAt": "2030-01-01"},
        {"entities": []},
        {"labels": ["Scanners"]},
    ],
)
def test_each_field_change_is_an_update(overrides):
    plan = build_memory_plan([spec(**overrides)], [make_vega_memory()], LABELS)
    assert len(plan.updates) == 1


def test_label_added_in_the_ui_is_removed_on_next_sync():
    current = make_vega_memory(
        labels=[
            {"id": MANAGED_LABEL_ID, "name": "detections-as-code"},
            {"id": OTHER_LABEL_ID, "name": "Scanners"},
        ]
    )
    assert len(build_memory_plan([spec()], [current], LABELS).updates) == 1


def test_label_names_match_without_case():
    current = make_vega_memory(
        labels=[
            {"id": MANAGED_LABEL_ID, "name": "detections-as-code"},
            {"id": OTHER_LABEL_ID, "name": "Scanners"},
        ]
    )
    assert build_memory_plan([spec(labels=["scanners"])], [current], LABELS).no_op_updates == 1


def test_unknown_label_blocks_only_that_memory():
    other = spec(title="Other")
    plan = build_memory_plan([spec(labels=["Nope"]), other], [make_vega_memory()], LABELS)
    assert [b.name for b in plan.blocked] == ["Approved vulnerability scanner"]
    assert plan.blocked[0].kind == "update"
    assert [c.name for c in plan.creates] == ["Other"]
    assert not plan.deletes


def test_managed_memory_without_a_file_is_deleted():
    plan = build_memory_plan([], [make_vega_memory()], LABELS)
    assert [d.external_id for d in plan.deletes] == ["MEM-K7QX2"]


def test_title_change_is_delete_plus_create():
    plan = build_memory_plan([spec(title="Renamed")], [make_vega_memory()], LABELS)
    assert [c.name for c in plan.creates] == ["Renamed"]
    assert len(plan.deletes) == 1


def test_duplicate_managed_titles_keep_the_first():
    first, second = make_vega_memory(id="a"), make_vega_memory(id="b")
    plan = build_memory_plan([spec()], [first, second], LABELS)
    assert plan.no_op_updates == 1
    assert [d.payload for d in plan.deletes] == ["b"]


def test_missing_managed_label_plans_creates():
    plan = build_memory_plan([spec()], [], [LABELS[1]])
    assert plan.managed_label_id is None
    assert len(plan.creates) == 1


def test_title_held_by_an_unlabelled_memory_blocks_the_create():
    released = make_vega_memory(id="released", vegaMemoryId="MEM-OLD1", labels=[])
    plan = build_memory_plan([spec()], [released], LABELS)
    assert not plan.creates and not plan.deletes
    assert plan.blocked[0].kind == "create" and plan.blocked[0].external_id == "MEM-OLD1"
    assert "without the 'detections-as-code' label" in plan.blocked[0].reason


def test_unlabelled_memories_are_never_touched():
    ui = make_vega_memory(id="ui", title="Written in the UI", labels=[])
    plan = build_memory_plan([], [ui], LABELS)
    assert not plan.deletes and not plan.updates and not plan.blocked


def test_planned_writes_carry_resolved_label_ids():
    plan = build_memory_plan(
        [spec(labels=["SCANNERS"], content="changed"), spec(title="New", labels=["Scanners"])],
        [make_vega_memory()],
        LABELS,
    )
    assert plan.updates[0].payload["labelIds"] == [OTHER_LABEL_ID, MANAGED_LABEL_ID]
    assert plan.creates[0].payload["labelIds"] == [OTHER_LABEL_ID, MANAGED_LABEL_ID]


def test_title_held_by_a_memory_before_the_label_exists_says_to_create_it():
    ui = make_vega_memory(labels=[])
    plan = build_memory_plan([spec()], [ui], [LABELS[1]])
    assert "does not exist yet: create 'detections-as-code'" in plan.blocked[0].reason


def test_duplicate_titles_in_the_repo_are_rejected(tmp_path):
    for name in ("a.yaml", "b.yaml"):
        (tmp_path / name).write_text("title: Same\ndescription: d\ncontent: c\n")
    with pytest.raises(ValueError, match="duplicate title"):
        load_yaml_memories([tmp_path])


def _denied() -> VegaAPIError:
    return VegaAPIError("GraphQL errors", [{"extensions": {"error_code_name": "ACCESS_DENIED"}}])


class FakeClient:
    def __init__(self, labels=None, memories=None, fail=None, denied=()):
        self.labels = list(LABELS if labels is None else labels)
        self.memories = memories or []
        self.fail = fail or {}
        self.denied = set(denied)
        self.calls: list[tuple[str, Any]] = []

    def _maybe_fail(self, op):
        if op in self.fail:
            raise VegaAPIError(f"GraphQL errors: {op} failed", self.fail[op])

    def list_labels(self):
        if "list_labels" in self.denied:
            raise _denied()
        return self.labels

    def get_memories(self):
        if "get_memories" in self.denied:
            raise _denied()
        return self.memories

    def create_label(self, name, color):
        self.calls.append(("create_label", name))
        self._maybe_fail("create_label")
        return {"id": "new-label", "name": name}

    def create_memory(self, payload):
        self.calls.append(("create", payload))
        self._maybe_fail("create")
        return {"vegaMemoryId": "MEM-NEW"}

    def update_memory(self, payload):
        self.calls.append(("update", payload))
        self._maybe_fail("update")
        return {}

    def delete_memory(self, memory_id):
        self.calls.append(("delete", memory_id))
        self._maybe_fail("delete")
        return {}


def test_deletes_run_before_updates_and_creates():
    plan = build_memory_plan(
        [spec(content="changed"), spec(title="New")],
        [make_vega_memory(), make_vega_memory(id="gone", title="Gone")],
        LABELS,
    )
    client = FakeClient()
    report = execute_memory_plan(client, plan)
    assert [c[0] for c in client.calls] == ["delete", "update", "create"]
    assert report.all_ok
    assert all(r.target == "memory" for r in report.results)


def test_every_write_carries_the_managed_label():
    plan = build_memory_plan([spec(content="changed"), spec(title="New", labels=["Scanners"])], [make_vega_memory()], LABELS)
    client = FakeClient()
    execute_memory_plan(client, plan)
    update, create = client.calls[0][1], client.calls[1][1]
    assert update["labelIds"] == [MANAGED_LABEL_ID]
    assert create["labelIds"] == [OTHER_LABEL_ID, MANAGED_LABEL_ID]


def test_first_create_makes_the_managed_label():
    plan = build_memory_plan([spec()], [], [])
    client = FakeClient(labels=[])
    execute_memory_plan(client, plan)
    assert client.calls[0] == ("create_label", "detections-as-code")
    assert client.calls[1][1]["labelIds"] == ["new-label"]


def test_label_creation_failure_fails_the_creates():
    plan = build_memory_plan([spec()], [], [])
    report = execute_memory_plan(FakeClient(labels=[], fail={"create_label": []}), plan)
    assert not report.all_ok
    assert "could not create" in report.failed[0].error
    assert "LabelsWrite" not in report.failed[0].error


def test_label_creation_error_reaches_every_create():
    plan = build_memory_plan([spec(), spec(title="B")], [], [])
    denied = [{"extensions": {"error_code_name": "ACCESS_DENIED"}}]
    report = execute_memory_plan(FakeClient(labels=[], fail={"create_label": denied}), plan)
    assert len(report.failed) == 2
    assert all("could not create the 'detections-as-code' label" in r.error for r in report.failed)


def test_memory_limit_error_explains_the_shared_cap():
    plan = build_memory_plan([spec()], [], LABELS)
    limit = [{"extensions": {"error_code_name": "MEMORY_LIMIT_REACHED"}}]
    report = execute_memory_plan(FakeClient(fail={"create": limit}), plan)
    assert "learned by Vega" in report.failed[0].error


def test_one_failure_does_not_stop_the_others():
    plan = build_memory_plan([spec(title="A"), spec(title="B")], [], LABELS)
    client = FakeClient(fail={"create": []})
    report = execute_memory_plan(client, plan)
    assert len(report.failed) == 2 and len(client.calls) == 2


def test_no_deletes_flag():
    plan = build_memory_plan([], [make_vega_memory()], LABELS)
    client = FakeClient()
    assert execute_memory_plan(client, plan, skip_deletes=True).results == []
    assert client.calls == []


def test_blocked_memories_are_planned_with_a_reason():
    plan = build_memory_plan([spec(labels=["Nope"])], [], LABELS)
    assert "not found in the tenant" in plan.blocked[0].reason


@pytest.mark.parametrize("op", ["get_memories", "list_labels"])
def test_access_denied_means_memories_unavailable(op):
    with pytest.raises(MemoriesUnavailable, match="LabelsRead"):
        fetch_memory_state(FakeClient(denied={op}))


def test_access_denied_in_a_message_alone_is_not_unavailable():
    class Client(FakeClient):
        def get_memories(self):
            raise VegaAPIError("GraphQL errors: title mentions ACCESS_DENIED")

    with pytest.raises(VegaAPIError):
        fetch_memory_state(Client())


def test_pr_repo_checks_report_duplicates_and_skip_broken_files(tmp_path, monkeypatch):
    from scripts.pr_validate import memory_folder_checks

    monkeypatch.chdir(tmp_path)
    mem = tmp_path / "memories"
    mem.mkdir()
    (mem / "a.yaml").write_text("title: Same\ndescription: d\ncontent: c\n")
    (mem / "b.yaml").write_text("title: Same\ndescription: d\ncontent: c\n")
    (mem / "c.yaml").write_text("title: Broken\nenabled: true\n")
    checks = memory_folder_checks(mem)
    assert [c.path for c in checks] == ["memories/b.yaml"]
    assert "duplicate title" in checks[0].schema_error


def _git(cwd, *args):
    import subprocess

    subprocess.run(["git", "-c", "user.email=t@t", "-c", "user.name=t", *args], cwd=cwd, check=True, capture_output=True)


@pytest.mark.parametrize(
    "change,warned",
    [("retitle", True), ("move_and_retitle", True), ("move", False), ("edit_content", False)],
)
def test_pr_lint_warns_when_a_memory_title_changes(tmp_path, monkeypatch, change, warned):
    from scripts.pr_validate import memory_title_change_checks

    monkeypatch.chdir(tmp_path)
    _git(tmp_path, "init", "-q")
    mem = tmp_path / "memories"
    mem.mkdir()
    (mem / "a.yaml").write_text("title: Old\ndescription: d\ncontent: c\n")
    _git(tmp_path, "add", "-A")
    _git(tmp_path, "commit", "-qm", "base")
    if change == "retitle":
        (mem / "a.yaml").write_text("title: New\ndescription: d\ncontent: c\n")
    elif change == "edit_content":
        (mem / "a.yaml").write_text("title: Old\ndescription: d\ncontent: changed\n")
    else:
        _git(tmp_path, "mv", "memories/a.yaml", "memories/b.yaml")
        if change == "move_and_retitle":
            (mem / "b.yaml").write_text("title: New\ndescription: d\ncontent: c\n")
    _git(tmp_path, "commit", "-qam", "change")
    checks = memory_title_change_checks(mem, "HEAD~1")
    assert bool(checks) is warned
    if warned:
        assert checks[0].schema_ok and "new MEM- id" in checks[0].warnings[0]


def test_pr_report_merges_checks_for_one_file():
    from scripts.pr_validate import FileCheck, Report

    report = Report()
    report.add(FileCheck(path="memories/a.yaml", schema_ok=True))
    report.add(FileCheck(path="memories/a.yaml", schema_ok=True, warnings=["renamed"]))
    report.add(FileCheck(path="memories/a.yaml", schema_ok=False, schema_error="duplicate"))
    assert len(report.checks) == 1
    assert not report.all_ok and report.checks[0].warnings == ["renamed"]
    assert report.checks[0].schema_error == "duplicate"
