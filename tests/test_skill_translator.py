from __future__ import annotations

import pytest

from scripts.skill_translator import (
    count_lines,
    parse_skill,
    to_create_input,
    to_update_input,
)

from .conftest import SKILL_BODY, SKILL_ID, make_skill_md


def test_frontmatter_and_body_map_to_the_create_payload():
    spec = parse_skill(make_skill_md(), "SKILL.md")
    assert to_create_input(spec) == {
        "externalId": SKILL_ID,
        "name": "Service account sign-in triage",
        "description": "Sign-ins by service accounts outside their fixed egress.",
        "type": "TRIAGE",
        "instructions": SKILL_BODY.strip(),
    }


def test_update_payload_targets_the_tenant_id_and_never_sends_tags():
    payload = to_update_input(parse_skill(make_skill_md(), "SKILL.md"), "tenant-id")
    assert payload["id"] == "tenant-id"
    assert "externalId" not in payload and "tags" not in payload


@pytest.mark.parametrize(
    "value,expected",
    [
        ("triage", "TRIAGE"),
        ("Investigation", "INVESTIGATION"),
        ("detection_generation", "DETECTION_GENERATION"),
        ("detection-generation", "DETECTION_GENERATION"),
        ("memory", "MEMORY"),
    ],
)
def test_type_is_case_insensitive(value, expected):
    assert parse_skill(make_skill_md(type=value), "SKILL.md").type.value == expected


def test_id_is_stored_in_canonical_form():
    spec = parse_skill(make_skill_md(id=SKILL_ID.upper()), "SKILL.md")
    assert spec.external_id == SKILL_ID


def test_crlf_and_bom_files_parse():
    raw = "﻿" + make_skill_md().replace("\n", "\r\n")
    assert parse_skill(raw, "SKILL.md").name == "Service account sign-in triage"


@pytest.mark.parametrize("missing", ["id", "name", "description", "type"])
def test_required_fields(missing):
    with pytest.raises(ValueError, match=f"missing required field '{missing}'"):
        parse_skill(make_skill_md(**{missing: None}), "SKILL.md")


@pytest.mark.parametrize(
    "raw,match",
    [
        ("no frontmatter here", "starts with YAML frontmatter"),
        ("---\nid: x\n", "starts with YAML frontmatter"),
        ("---\n- a\n---\nbody", "must be a YAML mapping"),
        ("---\nname: [\n---\nbody", "frontmatter YAML parse"),
    ],
)
def test_malformed_files(raw, match):
    with pytest.raises(ValueError, match=match):
        parse_skill(raw, "SKILL.md")


@pytest.mark.parametrize(
    "overrides,match",
    [
        ({"id": "not-a-uuid"}, "'id' must be a UUID"),
        ({"type": "alert"}, "invalid type 'alert'"),
        ({"name": "x" * 256}, "'name' must be 1-255"),
        ({"description": "'   '"}, "'description' must be a non-empty"),
        ({"category": "Triage"}, "unknown field 'category': use 'type'"),
        ({"tags": "[a]"}, "unknown field 'tags': labels on skills"),
        ({"version": "1.0.0"}, "unknown field 'version'"),
        ({"author": "Vega"}, "unknown field 'author'"),
        ({"bogus": "1"}, "allowed fields: description, id, name, type"),
    ],
)
def test_invalid_frontmatter(overrides, match):
    with pytest.raises(ValueError, match=match):
        parse_skill(make_skill_md(**overrides), "SKILL.md")


def test_empty_body_is_rejected():
    with pytest.raises(ValueError, match="must not be empty"):
        parse_skill(make_skill_md(body="\n\n"), "SKILL.md")


def test_instruction_line_cap_counts_like_the_server():
    assert count_lines("a\r\nb\rc\n") == 4
    parse_skill(make_skill_md(body="\n".join(["x"] * 500)), "SKILL.md")
    with pytest.raises(ValueError, match="at most 500 lines"):
        parse_skill(make_skill_md(body="\n".join(["x"] * 501)), "SKILL.md")


def test_body_whitespace_is_stripped_so_round_trips_are_stable():
    spec = parse_skill(make_skill_md(body="\n\n  # Steps\n\nDo it.\n\n\n"), "SKILL.md")
    assert spec.instructions == "# Steps\n\nDo it."


def test_every_unknown_key_is_named_at_once():
    raw = make_skill_md(version="1.0.0", author="Vega", category="Triage", type=None)
    with pytest.raises(ValueError) as e:
        parse_skill(raw, "SKILL.md")
    for key in ("version", "author", "category"):
        assert f"unknown field '{key}'" in str(e.value)
