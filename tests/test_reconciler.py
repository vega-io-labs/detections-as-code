from __future__ import annotations

from typing import Any

import pytest

from scripts.client import VegaAPIError
from scripts.plan import SyncReport
from scripts.reconciler import (
    BATCH_SIZE,
    build_plan,
    execute_plan,
    label_managed_detections,
)

from .conftest import (
    LIBRARY_ID,
    LIBRARY_NAME,
    MANAGED_LABEL_ID,
    make_library_yaml,
    make_vega,
    make_vega_library,
    make_yaml,
)


def test_identical_detection_is_a_no_op():
    plan = build_plan([make_yaml()], [make_vega()])
    assert plan.no_op_updates == 1
    assert not plan.creates and not plan.updates and not plan.deletes


def test_mode_change_is_an_update():
    plan = build_plan([make_yaml(mode="evidence")], [make_vega()])
    assert len(plan.updates) == 1
    assert plan.updates[0].payload["mode"] == "EVIDENCE"


def test_same_skills_in_any_order_is_a_no_op():
    current = make_vega(skills=[{"id": "s1"}, {"id": "s2"}])
    assert build_plan([make_yaml(skillIds=["s2", "s1"])], [current]).no_op_updates == 1


def test_new_detection_is_created_in_its_own_state():
    plan = build_plan([make_yaml(state="test_mode")], [])
    assert [c.payload["state"] for c in plan.creates] == ["TEST_MODE"]
    assert not plan.updates


def test_skill_change_is_an_update():
    plan = build_plan([make_yaml()], [make_vega(skills=[{"id": "s1"}])])
    assert plan.updates[0].payload["skillIds"] == []
    plan = build_plan([make_yaml(skillIds=["s9"])], [make_vega()])
    assert plan.updates[0].payload["skillIds"] == ["s9"]


def test_unlabelled_library_detections_are_never_deleted():
    library = make_vega(id="lib", externalId="lib-ext", createdBy={"principalType": "vega_library"})
    custom_orphan = make_vega(id="old", externalId="old-ext")
    plan = build_plan([make_yaml()], [make_vega(), library, custom_orphan])
    assert [d.external_id for d in plan.deletes] == ["old-ext"]


def test_missing_created_by_still_deletes_a_custom_orphan():
    orphan = make_vega(id="x", externalId="x-ext", createdBy=None)
    assert [d.external_id for d in build_plan([], [orphan]).deletes] == ["x-ext"]


def test_missing_description_in_yaml_never_diffs():
    current = make_vega(logicDescription="kept", attackScenario="kept too")
    assert build_plan([make_yaml()], [current]).no_op_updates == 1


def test_duplicate_skill_ids_from_the_api_do_not_diff():
    current = make_vega(skills=[{"id": "s1"}, {"id": "s1"}, {"id": "s2"}])
    assert build_plan([make_yaml(skillIds=["s1", "s2"])], [current]).no_op_updates == 1


WEBHOOK = "3f2b8c1e-5d4a-4e7b-9a6c-1d2e3f4a5b6c"


def test_ui_owned_escalation_and_webhooks_never_diff():
    current = make_vega(isAlwaysEscalatedToIncident=True, webhookIds=[WEBHOOK])
    assert build_plan([make_yaml()], [current]).no_op_updates == 1


def test_escalation_and_webhooks_set_in_the_file_are_enforced():
    current = make_vega(isAlwaysEscalatedToIncident=True, webhookIds=[WEBHOOK])
    plan = build_plan(
        [make_yaml(isAlwaysEscalatedToIncident=False, webhookIds=[])], [current]
    )
    assert plan.updates[0].payload["isAlwaysEscalatedToIncident"] is False
    assert plan.updates[0].payload["webhookIds"] == []
    same = build_plan(
        [make_yaml(isAlwaysEscalatedToIncident=True, webhookIds=[WEBHOOK.upper()])],
        [current],
    )
    assert same.no_op_updates == 1


def test_switch_to_evidence_turns_ui_escalation_off():
    current = make_vega(isAlwaysEscalatedToIncident=True)
    plan = build_plan([make_yaml(mode="evidence")], [current])
    assert plan.updates[0].payload["isAlwaysEscalatedToIncident"] is False
    settled = make_vega(mode="EVIDENCE")
    assert build_plan([make_yaml(mode="evidence")], [settled]).no_op_updates == 1


# ---- library detections ------------------------------------------------------

OTHER_LIBRARY_ID = "435fb46e-7b61-43f9-90e2-6085b95255c9"
GIT_LABEL = [{"id": MANAGED_LABEL_ID, "name": "Managed by Git"}]


def test_library_file_missing_from_the_tenant_is_added_in_its_state():
    plan = build_plan([make_library_yaml()], [])
    assert [(e.external_id, e.name, e.payload["state"]) for e in plan.library_adds] == [
        (LIBRARY_ID, LIBRARY_NAME, "TEST_MODE")
    ]
    assert not plan.creates and not plan.updates and not plan.library_states


def test_library_file_with_an_unknown_id_is_blocked_not_created():
    plan = build_plan([make_library_yaml()], [], frozenset({LIBRARY_ID}))
    assert not plan.library_adds and not plan.creates
    assert [(b.kind, b.external_id) for b in plan.blocked] == [("add", LIBRARY_ID)]
    assert "no Vega library detection has this id" in plan.blocked[0].reason


def test_unknown_ids_only_block_their_own_file():
    plan = build_plan(
        [make_library_yaml(), make_library_yaml(id=OTHER_LIBRARY_ID)], [], frozenset({OTHER_LIBRARY_ID})
    )
    assert [e.external_id for e in plan.library_adds] == [LIBRARY_ID]
    assert [b.external_id for b in plan.blocked] == [OTHER_LIBRARY_ID]


def test_library_detection_in_the_same_state_is_a_no_op():
    plan = build_plan([make_library_yaml()], [make_vega_library()])
    assert plan.no_op_updates == 1
    assert not plan.library_adds and not plan.library_states and not plan.deletes


@pytest.mark.parametrize("state,expected", [("enabled", "ENABLED"), ("disabled", "DISABLED")])
def test_library_state_change_is_planned_by_library_id(state, expected):
    plan = build_plan([make_library_yaml(state=state)], [make_vega_library()])
    assert [(e.external_id, e.payload["state"]) for e in plan.library_states] == [(LIBRARY_ID, expected)]
    assert not plan.updates


def test_library_file_never_sends_fields_even_when_vega_differs():
    vega = make_vega_library(severity="CRITICAL", name="Renamed by Vega", cells=[])
    plan = build_plan([make_library_yaml()], [vega])
    assert plan.no_op_updates == 1 and not plan.updates


def test_library_file_for_a_detached_detection_is_blocked_and_kept():
    detached = make_vega_library(createdBy={"principalType": "user"})
    plan = build_plan([make_library_yaml(state="enabled")], [detached])
    assert [(b.kind, b.external_id) for b in plan.blocked] == [("set_state", LIBRARY_ID)]
    assert "no longer connected to the Vega library" in plan.blocked[0].reason
    assert not plan.updates and not plan.deletes and not plan.library_states


def test_custom_file_claiming_a_library_detection_is_blocked_not_updated():
    custom = make_yaml(id=LIBRARY_ID, name=LIBRARY_NAME, severity="high")
    plan = build_plan([custom], [make_vega_library()])
    assert [(b.kind, b.external_id) for b in plan.blocked] == [("update", LIBRARY_ID)]
    assert "library: true" in plan.blocked[0].reason
    assert not plan.updates and not plan.creates and not plan.deletes


def test_labelled_library_detection_without_a_file_is_removed():
    plan = build_plan([], [make_vega_library(labels=GIT_LABEL)])
    assert [(d.external_id, d.payload) for d in plan.deletes] == [
        (LIBRARY_ID, make_vega_library()["id"])
    ]


def test_library_detection_with_other_labels_only_is_kept():
    assert not build_plan([], [make_vega_library()]).deletes


def test_custom_detection_without_a_file_is_removed_label_or_not():
    plan = build_plan([], [make_vega(), make_vega(id="b", externalId="b-ext", labels=GIT_LABEL)])
    assert sorted(d.external_id for d in plan.deletes) == sorted(["b-ext", make_yaml()["id"]])


def test_library_and_custom_files_plan_side_by_side():
    plan = build_plan(
        [make_yaml(severity=1), make_library_yaml(), make_library_yaml(id=OTHER_LIBRARY_ID, state="enabled")],
        [make_vega(), make_vega_library(id="x", externalId=OTHER_LIBRARY_ID, state="DISABLED")],
    )
    assert len(plan.updates) == 1
    assert [e.external_id for e in plan.library_adds] == [LIBRARY_ID]
    assert [e.external_id for e in plan.library_states] == [OTHER_LIBRARY_ID]
    assert "library_adds=1 library_states=1" in plan.summary()


class LibraryClient:
    def __init__(self, responses: list[Any] | None = None):
        self.calls: list[tuple[list[str], str]] = []
        self.responses = responses or []

    def create_detections(self, detections):
        raise AssertionError("library files are never created")

    def update_detections(self, detections):
        raise AssertionError("library files are never updated")

    def set_library_detections_state(self, ids, state):
        self.calls.append((list(ids), state))
        if self.responses:
            response = self.responses.pop(0)
            if isinstance(response, Exception):
                raise response
            return response
        return {
            "results": [
                {"libraryDetectionId": i, "status": "ADDED", "detection": {"id": "inst-" + i}} for i in ids
            ],
            "userErrors": [],
        }


def _results(report: SyncReport) -> list[tuple[str, str, bool, str | None]]:
    return [(r.kind, r.external_id, r.success, r.error) for r in report.results]


def test_adds_and_state_changes_share_one_call_per_state():
    plan = build_plan(
        [make_library_yaml(), make_library_yaml(id=OTHER_LIBRARY_ID, state="test_mode")],
        [make_vega_library(id="x", externalId=OTHER_LIBRARY_ID, state="ENABLED")],
    )
    client = LibraryClient([
        {"results": [
            {"libraryDetectionId": LIBRARY_ID, "status": "ADDED", "detection": {"id": "new"}},
            {"libraryDetectionId": OTHER_LIBRARY_ID, "status": "UPDATED", "detection": {"id": "x"}},
        ], "userErrors": []},
    ])
    report = execute_plan(client, plan)
    assert client.calls == [([LIBRARY_ID, OTHER_LIBRARY_ID], "TEST_MODE")]
    assert _results(report) == [("add", LIBRARY_ID, True, None), ("set_state", OTHER_LIBRARY_ID, True, None)]
    assert report.results[0].object_id == "new"


def test_each_state_gets_its_own_call():
    plan = build_plan(
        [make_library_yaml(state="enabled"), make_library_yaml(id=OTHER_LIBRARY_ID, state="disabled")], []
    )
    client = LibraryClient()
    execute_plan(client, plan)
    assert client.calls == [([LIBRARY_ID], "ENABLED"), ([OTHER_LIBRARY_ID], "DISABLED")]


def test_unchanged_counts_as_success():
    plan = build_plan([make_library_yaml(state="enabled")], [make_vega_library()])
    client = LibraryClient([{"results": [
        {"libraryDetectionId": LIBRARY_ID, "status": "UNCHANGED", "detection": {"id": "x"}}], "userErrors": []}])
    assert _results(execute_plan(client, plan)) == [("set_state", LIBRARY_ID, True, None)]


def test_a_failed_library_detection_reports_its_user_error_and_the_rest_succeed():
    plan = build_plan([make_library_yaml(), make_library_yaml(id=OTHER_LIBRARY_ID)], [])
    client = LibraryClient([{"results": [
        {"libraryDetectionId": LIBRARY_ID, "status": "ADDED", "detection": {"id": "a"}},
        {"libraryDetectionId": OTHER_LIBRARY_ID, "status": "FAILED", "detection": None},
    ], "userErrors": [{"code": "NOT_FOUND", "message": f"no library detection has ID {OTHER_LIBRARY_ID}",
                       "path": ["input", "libraryDetectionIds", "1"]}]}])
    assert _results(execute_plan(client, plan)) == [
        ("add", LIBRARY_ID, True, None),
        ("add", OTHER_LIBRARY_ID, False, f"NOT_FOUND: no library detection has ID {OTHER_LIBRARY_ID}"),
    ]


def test_failed_without_a_user_error_still_says_what_happened():
    plan = build_plan([make_library_yaml()], [])
    client = LibraryClient([{"results": [{"libraryDetectionId": LIBRARY_ID, "status": "FAILED"}], "userErrors": []}])
    assert _results(execute_plan(client, plan)) == [
        ("add", LIBRARY_ID, False, "library detection not set to TEST_MODE (status FAILED)")
    ]


def test_a_missing_result_is_a_failure_not_a_silent_success():
    plan = build_plan([make_library_yaml()], [])
    client = LibraryClient([{"results": [], "userErrors": []}])
    assert _results(execute_plan(client, plan))[0][2] is False


def test_a_rejected_call_fails_only_its_own_detections():
    plan = build_plan(
        [make_library_yaml(state="enabled"), make_library_yaml(id=OTHER_LIBRARY_ID, state="disabled")], []
    )
    client = LibraryClient([VegaAPIError("GraphQL errors: detection limit reached")])
    report = execute_plan(client, plan)
    assert _results(report)[0] == (
        "add", LIBRARY_ID, False, "batch API error: GraphQL errors: detection limit reached"
    )
    assert _results(report)[1] == ("add", OTHER_LIBRARY_ID, True, None)


def test_more_than_a_batch_of_library_files_is_split():
    ids = [f"00000000-0000-4000-8000-{i:012d}" for i in range(BATCH_SIZE + 5)]
    plan = build_plan([make_library_yaml(id=i) for i in ids], [])
    client = LibraryClient()
    report = execute_plan(client, plan)
    assert [len(c[0]) for c in client.calls] == [BATCH_SIZE, 5]
    assert len(report.succeeded) == BATCH_SIZE + 5


def test_library_deletes_run_with_the_rest_and_honour_no_deletes():
    class DeleteClient(LibraryClient):
        deleted: list[str] = []

        def delete_detection(self, detection_id):
            self.deleted.append(detection_id)
            return {"deletedDetectionId": detection_id}

    plan = build_plan([], [make_vega_library(labels=GIT_LABEL)])
    client = DeleteClient()
    assert execute_plan(client, plan, skip_deletes=True).results == []
    assert _results(execute_plan(client, plan)) == [("delete", LIBRARY_ID, True, None)]
    assert client.deleted == [make_vega_library()["id"]]


class LabelClient:
    def __init__(self):
        self.attached: list[list[str]] = []

    def attach_detection_labels(self, ids, label_ids):
        self.attached.append(sorted(ids))


class FixedLabel:
    def id(self):
        return MANAGED_LABEL_ID


def test_added_and_adopted_library_detections_get_the_git_label():
    plan = build_plan([make_library_yaml(), make_library_yaml(id=OTHER_LIBRARY_ID, state="test_mode")],
                      [make_vega_library(id="adopted", externalId=OTHER_LIBRARY_ID)])
    report = execute_plan(LibraryClient(), plan)
    client = LabelClient()
    vega = [make_vega_library(id="adopted", externalId=OTHER_LIBRARY_ID)]
    label_managed_detections({LIBRARY_ID, OTHER_LIBRARY_ID}, vega, report, client, FixedLabel())
    assert client.attached == [sorted(["adopted", "inst-" + LIBRARY_ID])]


def test_an_added_library_detection_read_back_as_null_is_labelled_next_run():
    plan = build_plan([make_library_yaml()], [])
    client = LibraryClient([{"results": [{"libraryDetectionId": LIBRARY_ID, "status": "ADDED", "detection": None}],
                             "userErrors": []}])
    report = execute_plan(client, plan)
    assert report.all_ok and report.results[0].object_id is None
    labels = LabelClient()
    label_managed_detections({LIBRARY_ID}, [], report, labels, FixedLabel())
    assert labels.attached == []
    label_managed_detections({LIBRARY_ID}, [make_vega_library()], SyncReport(), labels, FixedLabel())
    assert labels.attached == [[make_vega_library()["id"]]]

