from __future__ import annotations

from scripts.reconciler import build_plan

from .conftest import make_vega, make_yaml


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


def test_library_detections_are_never_deleted():
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
