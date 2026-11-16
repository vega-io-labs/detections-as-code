from __future__ import annotations

import pytest

from scripts.translator import yaml_to_create_input, yaml_to_update_input

from .conftest import make_yaml


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
