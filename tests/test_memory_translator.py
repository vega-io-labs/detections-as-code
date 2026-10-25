from __future__ import annotations

from datetime import date, datetime, timezone

import pytest

from scripts.memory_translator import (
    memory_warnings,
    parse_memory,
    to_create_input,
    to_update_input,
)

from .conftest import make_memory_yaml


def test_minimal_memory_defaults_to_enabled_without_expiry():
    spec = parse_memory(
        {"title": "t", "description": "d", "content": "c"}, "f.yaml"
    )
    payload = to_create_input(spec, ["label"])
    assert payload == {
        "title": "t",
        "description": "d",
        "content": "c",
        "status": "ENABLED",
        "entities": [],
        "labelIds": ["label"],
    }


def test_block_scalar_newlines_are_stripped():
    spec = parse_memory(make_memory_yaml(), "f.yaml")
    assert not spec.content.endswith("\n")


@pytest.mark.parametrize("missing", ["title", "description", "content"])
def test_required_fields(missing):
    doc = make_memory_yaml()
    del doc[missing]
    with pytest.raises(ValueError, match=f"missing required field '{missing}'"):
        parse_memory(doc, "f.yaml")


@pytest.mark.parametrize(
    "field,limit", [("title", 150), ("description", 300), ("content", 5000)]
)
def test_length_limits(field, limit):
    parse_memory(make_memory_yaml(**{field: "x" * limit}), "f.yaml")
    with pytest.raises(ValueError, match=f"1-{limit} characters"):
        parse_memory(make_memory_yaml(**{field: "x" * (limit + 1)}), "f.yaml")


def test_description_must_be_one_line():
    with pytest.raises(ValueError, match="single line"):
        parse_memory(make_memory_yaml(description="a\nb"), "f.yaml")


@pytest.mark.parametrize(
    "key,hint",
    [("enabled", "status"), ("name", "title"), ("id", "title"), ("colour", "allowed")],
)
def test_unknown_fields_are_rejected_with_a_hint(key, hint):
    with pytest.raises(ValueError, match=hint):
        parse_memory(make_memory_yaml(**{key: "x"}), "f.yaml")


def test_status():
    assert parse_memory(make_memory_yaml(status="Disabled"), "f").status.value == "DISABLED"
    with pytest.raises(ValueError, match="enabled|disabled"):
        parse_memory(make_memory_yaml(status="test_mode"), "f")
    with pytest.raises(ValueError, match="boolean"):
        parse_memory(make_memory_yaml(status=False), "f")


@pytest.mark.parametrize(
    "raw,expected",
    [
        ("2027-01-31T18:00:00Z", "2027-01-31T18:00:00Z"),
        ("2027-01-31T20:00:00+02:00", "2027-01-31T18:00:00Z"),
        ("2027-01-31", "2027-01-31T00:00:00Z"),
        (date(2027, 1, 31), "2027-01-31T00:00:00Z"),
        (datetime(2027, 1, 31, 18, tzinfo=timezone.utc), "2027-01-31T18:00:00Z"),
    ],
)
def test_expires_at_shapes(raw, expected):
    spec = parse_memory(make_memory_yaml(expiresAt=raw), "f")
    assert to_create_input(spec, [])["expiresAt"] == expected


def test_bad_expires_at():
    with pytest.raises(ValueError, match="ISO 8601"):
        parse_memory(make_memory_yaml(expiresAt="next tuesday"), "f")


def test_past_expiry_is_a_warning_not_an_error():
    spec = parse_memory(make_memory_yaml(expiresAt="2020-01-01"), "f")
    assert memory_warnings(spec)
    assert not memory_warnings(parse_memory(make_memory_yaml(), "f"))


def test_entities():
    spec = parse_memory(make_memory_yaml(), "f")
    assert to_create_input(spec, [])["entities"] == [
        {"type": "DEVICE", "value": "scanner-01"},
        {"type": "IP", "value": "192.0.2.10"},
    ]
    with pytest.raises(ValueError, match="account|device|ip|domain"):
        parse_memory(make_memory_yaml(entities=[{"type": "url", "value": "x"}]), "f")
    with pytest.raises(ValueError, match="at most 50"):
        parse_memory(
            make_memory_yaml(entities=[{"type": "ip", "value": str(i)} for i in range(51)]),
            "f",
        )


def test_case_insensitive_duplicate_entity_is_rejected():
    entities = [{"type": "account", "value": "Alice"}, {"type": "ACCOUNT", "value": "alice"}]
    with pytest.raises(ValueError, match="duplicated"):
        parse_memory(make_memory_yaml(entities=entities), "f")


def test_labels():
    assert parse_memory(make_memory_yaml(labels=["Scanners"]), "f").labels == ("Scanners",)
    with pytest.raises(ValueError, match="added by the sync"):
        parse_memory(make_memory_yaml(labels=["detections-as-code"]), "f")
    with pytest.raises(ValueError, match="duplicated"):
        parse_memory(make_memory_yaml(labels=["a", "a"]), "f")


def test_update_payload_clears_expiry_explicitly():
    payload = to_update_input(parse_memory(make_memory_yaml(), "f"), "mem-id", ["l"])
    assert payload["id"] == "mem-id"
    assert "expiresAt" in payload and payload["expiresAt"] is None
