from __future__ import annotations

import pytest
import yaml

from scripts.pr_validate import schema_check
from scripts.translator import (
    create_only_warnings,
    library_state_input,
    validate_detection_file,
    yaml_to_create_input,
    yaml_to_update_input,
)

from .conftest import LIBRARY_ID, LIBRARY_NAME, make_library_yaml, make_yaml


def test_create_payload_sends_mode_and_skill_ids_not_type():
    payload = yaml_to_create_input(make_yaml())
    assert payload["mode"] == "ALERT"
    assert payload["skillIds"] == []
    assert "type" not in payload


@pytest.mark.parametrize(
    ("value", "expected"),
    [("alert", "ALERT"), ("Evidence", "EVIDENCE"), ("MONITOR", "MONITOR"), (None, "ALERT")],
)
def test_mode_values(value, expected):
    yaml_doc = make_yaml()
    if value is not None:
        yaml_doc["mode"] = value
    assert yaml_to_create_input(yaml_doc)["mode"] == expected
    assert yaml_to_update_input(yaml_doc)["mode"] == expected


@pytest.mark.parametrize(
    ("value", "expected"),
    [("enabled", "ENABLED"), ("disabled", "DISABLED"), ("test_mode", "TEST_MODE"), ("test", "TEST_MODE")],
)
def test_state_is_sent_on_create_and_update(value, expected):
    yaml_doc = make_yaml(state=value)
    assert yaml_to_create_input(yaml_doc)["state"] == expected
    assert yaml_to_update_input(yaml_doc)["state"] == expected


@pytest.mark.parametrize("value", ["signal", "finding", "", 3])
def test_invalid_mode_is_rejected(value):
    with pytest.raises(ValueError, match="invalid mode"):
        yaml_to_create_input(make_yaml(mode=value))


def test_stale_type_key_is_rejected_with_guidance():
    with pytest.raises(ValueError, match="'type' is no longer accepted.*'mode'"):
        yaml_to_create_input(make_yaml(type="alert"))


def test_skill_ids_are_sent_as_given():
    ids = ["019e4c2b-7a10-7d3e-9c1f-2b6a8e0f4d11", "019e4c2b-7a10-7d3e-9c1f-2b6a8e0f4d12"]
    assert yaml_to_create_input(make_yaml(skillIds=ids))["skillIds"] == ids
    assert yaml_to_update_input(make_yaml(skillIds=ids))["skillIds"] == ids


@pytest.mark.parametrize(
    ("skill_ids", "message"),
    [
        (["a", "a"], "duplicated"),
        ([""], "non-empty string"),
        ([42], "non-empty string"),
        ([f"skill-{i}" for i in range(21)], "at most 20"),
    ],
)
def test_invalid_skill_ids_are_rejected(skill_ids, message):
    with pytest.raises(ValueError, match=message):
        yaml_to_create_input(make_yaml(skillIds=skill_ids))


def test_update_payload_omits_empty_descriptions():
    payload = yaml_to_update_input(make_yaml())
    assert "logicDescription" not in payload
    assert "attackScenario" not in payload
    create = yaml_to_create_input(make_yaml())
    assert create["logicDescription"] == "" and create["attackScenario"] == ""


def test_update_payload_keeps_descriptions_when_set():
    payload = yaml_to_update_input(make_yaml(logicDescription="what", attackScenario="why"))
    assert payload["logicDescription"] == "what"
    assert payload["attackScenario"] == "why"


WEBHOOK = "3f2b8c1e-5d4a-4e7b-9a6c-1d2e3f4a5b6c"


def test_escalation_and_webhooks_are_not_sent_when_absent():
    for build in (yaml_to_create_input, yaml_to_update_input):
        payload = build(make_yaml())
        assert "isAlwaysEscalatedToIncident" not in payload
        assert "webhookIds" not in payload


def test_escalation_and_webhooks_are_sent_when_set():
    payload = yaml_to_update_input(
        make_yaml(isAlwaysEscalatedToIncident=False, webhookIds=[WEBHOOK.upper()])
    )
    assert payload["isAlwaysEscalatedToIncident"] is False
    assert payload["webhookIds"] == [WEBHOOK]
    assert yaml_to_update_input(make_yaml(webhookIds=[]))["webhookIds"] == []


@pytest.mark.parametrize("mode", ["evidence", "monitor"])
def test_non_alert_modes_always_send_escalation_off(mode):
    payload = yaml_to_update_input(make_yaml(mode=mode))
    assert payload["isAlwaysEscalatedToIncident"] is False


@pytest.mark.parametrize(
    "overrides, message",
    [
        ({"isAlwaysEscalatedToIncident": "yes"}, "must be true or false"),
        ({"isAlwaysEscalatedToIncident": True, "mode": "evidence"}, "only allowed in alert mode"),
        ({"webhookIds": ["not-a-uuid"]}, "must be the UUID"),
        ({"webhookIds": [WEBHOOK, WEBHOOK.upper()]}, "is duplicated"),
        ({"webhookIds": [f"{i:08d}-0000-4000-8000-000000000000" for i in range(21)]}, "at most 20"),
    ],
)
def test_invalid_escalation_and_webhooks_are_rejected(overrides, message):
    with pytest.raises(ValueError, match=message):
        yaml_to_create_input(make_yaml(**overrides))


@pytest.mark.parametrize("mode", ["evidence", "monitor"])
def test_skills_outside_alert_mode_are_rejected(mode):
    with pytest.raises(ValueError, match="must be empty in"):
        yaml_to_create_input(make_yaml(mode=mode, skillIds=["s1"]))
    assert yaml_to_create_input(make_yaml(mode=mode, skillIds=[]))["skillIds"] == []


# ---- library files -----------------------------------------------------------

@pytest.mark.parametrize(
    "state,expected",
    [("enabled", "ENABLED"), ("disabled", "DISABLED"), ("test_mode", "TEST_MODE"),
     ("test", "TEST_MODE"), ("TEST-MODE", "TEST_MODE"), ("Enabled", "ENABLED")],
)
def test_library_file_becomes_a_library_state_input(state, expected):
    assert library_state_input(make_library_yaml(state=state)) == {
        "libraryDetectionId": LIBRARY_ID, "name": LIBRARY_NAME, "state": expected,
    }


def test_library_file_without_a_name_is_named_by_its_id():
    doc = make_library_yaml()
    del doc["name"]
    assert library_state_input(doc)["name"] == LIBRARY_ID


@pytest.mark.parametrize("value", [False, "true", "yes", 1, None])
def test_library_must_be_true(value):
    with pytest.raises(ValueError, match="'library' must be true"):
        library_state_input(make_library_yaml(library=value))


@pytest.mark.parametrize(
    "bad_id",
    [LIBRARY_ID.upper(), "root-login", "019e0000-0000-7000-8000-00000000000", f"{LIBRARY_ID}x", 42],
)
def test_library_id_must_be_a_lowercase_uuid(bad_id):
    with pytest.raises(ValueError, match="must be its id in the Vega library"):
        library_state_input(make_library_yaml(id=bad_id))


def test_library_file_without_an_id_fails():
    doc = make_library_yaml()
    del doc["id"]
    with pytest.raises(ValueError, match="missing required field 'id'"):
        library_state_input(doc)


def test_library_id_with_spaces_around_it_is_trimmed():
    assert library_state_input(make_library_yaml(id=f"  {LIBRARY_ID} "))["libraryDetectionId"] == LIBRARY_ID


def test_every_field_but_state_is_rejected_on_a_library_file_and_named():
    doc = make_library_yaml(severity="high", query="@x", skillIds=["s"], cells=[])
    with pytest.raises(ValueError) as e:
        library_state_input(doc)
    assert "'cells', 'query', 'severity', 'skillIds' cannot be set" in str(e.value)
    assert "Only 'state' is synced" in str(e.value)


@pytest.mark.parametrize("state", [None, "draft", "on", ""])
def test_library_state_is_required_and_must_be_known(state):
    with pytest.raises(ValueError, match="state"):
        library_state_input(make_library_yaml(state=state))


def test_library_state_key_missing_fails():
    doc = make_library_yaml()
    del doc["state"]
    with pytest.raises(ValueError, match="missing required field 'state'"):
        library_state_input(doc)


@pytest.mark.parametrize("name", ["", "   ", 7, ["a"]])
def test_library_name_must_be_a_non_empty_string(name):
    with pytest.raises(ValueError, match="'name' must be a non-empty string"):
        library_state_input(make_library_yaml(name=name))


def test_validate_detection_file_picks_the_library_rules():
    validate_detection_file(make_library_yaml())
    validate_detection_file(make_yaml())
    with pytest.raises(ValueError, match="missing required field 'severity'"):
        validate_detection_file({"id": "x", "name": "n", "state": "enabled"})


def test_removing_library_true_makes_it_an_incomplete_custom_file():
    doc = make_library_yaml()
    del doc["library"]
    with pytest.raises(ValueError, match="missing required field"):
        validate_detection_file(doc)


def test_library_files_have_no_create_warnings():
    assert create_only_warnings(make_library_yaml()) == []


def test_pr_check_accepts_a_library_file_and_names_a_bad_one(tmp_path):
    good = tmp_path / "good.yaml"
    good.write_text(yaml.safe_dump(make_library_yaml()))
    bad = tmp_path / "bad.yaml"
    bad.write_text(yaml.safe_dump(make_library_yaml(query="@x | take 1")))
    ok = schema_check(good)
    assert ok.schema_ok and ok.warnings == []
    failed = schema_check(bad)
    assert not failed.schema_ok and "'query' cannot be set on a Vega library detection" in failed.schema_error
