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
