from __future__ import annotations

import pytest
import yaml

from scripts.export import (
    DETECTION_KEY_ORDER,
    MEMORY_KEY_ORDER,
    ExportError,
    detection_file,
    detection_matches,
    memory_file,
    render,
    skill_file,
    slug,
    verify_detection,
    verify_memory,
    verify_skill,
)
from scripts.labels import label_ids_by_name
from scripts.memory_translator import parse_memory
from scripts.skill_translator import parse_skill

from .conftest import (
    LABELS,
    MANAGED_LABEL_ID,
    OTHER_LABEL_ID,
    SKILL_ID,
    make_memory_yaml,
    make_skill_md,
    make_vega,
    make_vega_memory,
    make_vega_skill,
    make_yaml,
)

LABEL_IDS = label_ids_by_name(LABELS)


def exported(vega, existing_text=None, tenant_to_repo=None):
    existing = yaml.safe_load(existing_text) if existing_text else None
    doc = detection_file(vega, existing, tenant_to_repo or {})
    text = render(doc, existing_text, DETECTION_KEY_ORDER)
    repo_to_tenant = {v: k for k, v in (tenant_to_repo or {}).items()}
    verify_detection(text, vega, repo_to_tenant)
    return text


def test_a_matching_file_is_recognised_as_a_no_op():
    assert detection_matches(make_yaml(), make_vega(), {})
    assert not detection_matches(make_yaml(severity=1), make_vega(), {})


def test_an_invalid_file_never_matches():
    assert not detection_matches(make_yaml(severity=9), make_vega(), {})


def test_fresh_detection_uses_the_template_shape():
    vega = make_vega(
        severity="HIGH",
        state="TEST_MODE",
        mode="EVIDENCE",
        frequencyCron="@every 1h30m",
        lookBackSeconds=7200,
        mitreTechniques=["T1078"],
        logicDescription="what it matches",
        deduplicationFields=["actor.user.name"],
        deduplicationWindowSeconds=900,
        groupingField="device.hostname",
        groupingThreshold=25,
        actorFields=["actor.user.name"],
        cells=[{"name": "trigger", "query": "@CloudTrail\n| where a == 1", "trigger": True}],
    )
    text = exported(vega)
    assert text == (
        'id: "019e0000-0000-7000-8000-000000000001"\n'
        'name: "Root login"\n'
        "severity: 3\n"
        'state: "test_mode"\n'
        'frequencyCron: "1h30m"\n'
        "lookBackSeconds: 7200\n"
        'mode: "evidence"\n'
        'logicDescription: "what it matches"\n'
        "mitreTechniques:\n"
        '  - "T1078"\n'
        "deduplicationFields:\n"
        '  - "actor.user.name"\n'
        "deduplicationWindowSeconds: 900\n"
        'groupingField: "device.hostname"\n'
        "groupingThreshold: 25\n"
        "actorFields:\n"
        '  - "actor.user.name"\n'
        "query: |-\n"
        "  @CloudTrail\n"
        "  | where a == 1\n"
    )


def test_fresh_detection_omits_defaults():
    text = exported(make_vega())
    doc = yaml.safe_load(text)
    assert set(doc) == {"id", "name", "severity", "state", "frequencyCron", "lookBackSeconds", "query"}
    assert doc["frequencyCron"] == "5m"


@pytest.mark.parametrize(
    "vega_value,expected",
    [("@every 5m", "5m"), ("@every 2h", "2h"), ("@every 1h5m", "1h5m"), ("@every 90s", "@every 90s"), ("0 */2 * * *", "0 */2 * * *"), ("@daily", "@daily")],
)
def test_frequency_is_written_the_way_people_write_it(vega_value, expected):
    doc = detection_file(make_vega(frequencyCron=vega_value, lookBackSeconds=86400), None, {})
    assert doc["frequencyCron"] == expected


def test_an_equivalent_frequency_in_the_file_is_kept():
    doc = detection_file(make_vega(frequencyCron="@every 1h"), {"frequencyCron": "60m"}, {})
    assert doc["frequencyCron"] == "60m"


def test_in_place_edit_keeps_comments_order_and_untouched_values():
    existing = (
        "# Owner: identity team\n"
        'id: "019e0000-0000-7000-8000-000000000001"\n'
        "name: Root login   # trailing comment\n"
        "severity: high\n"
        'state: "enabled"\n'
        "frequencyCron: 5m\n"
        "lookBackSeconds: 300\n"
        "mitreTechniques: [T1078.004, T1078]\n"
        "owner: identity\n"
        "query: |-\n"
        "  @CloudTrail | where event_name == 'ConsoleLogin'\n"
    )
    vega = make_vega(
        name="Root console login",
        severity="CRITICAL",
        mitreTechniques=["T1078", "T1078.004"],
        references=["https://example.com"],
    )
    text = exported(vega, existing)
    assert text == (
        "# Owner: identity team\n"
        'id: "019e0000-0000-7000-8000-000000000001"\n'
        "name: Root console login # trailing comment\n"
        "severity: critical\n"
        'state: "enabled"\n'
        "frequencyCron: 5m\n"
        "lookBackSeconds: 300\n"
        "mitreTechniques: [T1078.004, T1078]\n"
        "references:\n"
        '  - "https://example.com"\n'
        "owner: identity\n"
        "query: |-\n"
        "  @CloudTrail | where event_name == 'ConsoleLogin'\n"
    )


def test_in_place_edit_removes_what_the_tenant_no_longer_has():
    existing = yaml.safe_dump(make_yaml(groupingField="x", references=["a"], deduplicationWindowSeconds=60, mode="evidence"))
    doc = yaml.safe_load(exported(make_vega(), existing))
    for key in ("groupingField", "references", "deduplicationWindowSeconds", "mode"):
        assert key not in doc, key


def test_defaults_the_file_spells_out_are_kept():
    existing = yaml.safe_dump(make_yaml(references=[], deduplicationWindowSeconds=0, mode="alert", groupingThreshold=10, skillIds=[]))
    text = exported(make_vega(name="Renamed"), existing)
    doc = yaml.safe_load(text)
    assert doc["references"] == [] and doc["deduplicationWindowSeconds"] == 0
    assert doc["mode"] == "alert" and doc["groupingThreshold"] == 10 and doc["skillIds"] == []


def test_list_items_keep_their_place_and_comments_when_one_is_added():
    existing = (
        'id: "019e0000-0000-7000-8000-000000000001"\n'
        'name: "Root login"\n'
        "severity: 4\n"
        'state: "enabled"\n'
        'frequencyCron: "5m"\n'
        "lookBackSeconds: 300\n"
        "mitreTechniques:\n"
        '  - "T1078"  # valid accounts\n'
        '  - "T1110"  # brute force, dropped in the tenant\n'
        "query: |-\n"
        "  @CloudTrail | where event_name == 'ConsoleLogin'\n"
    )
    vega = make_vega(mitreTechniques=["T1098", "T1078"])
    text = exported(vega, existing)
    assert (
        "mitreTechniques:\n"
        '  - "T1078"  # valid accounts\n'
        '  - "T1098"\n'
        "query:"
    ) in text


def test_ordered_fields_follow_the_tenant_order():
    existing = yaml.safe_dump(make_yaml(actorFields=["a", "b"]))
    doc = yaml.safe_load(exported(make_vega(actorFields=["b", "a"]), existing))
    assert doc["actorFields"] == ["b", "a"]


def test_skill_ids_are_written_as_repository_ids_and_keep_file_order():
    vega = make_vega(skills=[{"id": "t2"}, {"id": "t1"}, {"id": "t1"}])
    existing = yaml.safe_dump(make_yaml(skillIds=["s1", "s2"]))
    doc = yaml.safe_load(exported(vega, existing, {"t1": "s1", "t2": "s2"}))
    assert doc["skillIds"] == ["s1", "s2"]
    fresh = yaml.safe_load(exported(vega, None, {"t1": "s1"}))
    assert fresh["skillIds"] == ["s1", "t2"]


def test_multi_cell_detection_keeps_short_cell_references():
    vega = make_vega(
        cells=[
            {"name": "State", "query": "@X | where a", "trigger": False},
            {"name": "trigger", "query": "@cells:ref1/State | where b", "trigger": True},
        ]
    )
    doc = yaml.safe_load(exported(vega))
    assert "query" not in doc
    assert doc["cells"] == [
        {"name": "State", "query": "@X | where a"},
        {"name": "trigger", "query": "@State | where b", "trigger": True},
    ]


def test_cells_file_stays_in_cells_form_and_keeps_its_cell_order():
    existing = yaml.safe_dump(
        make_yaml(
            query=None,
            cells=[
                {"name": "trigger", "query": "@cells:ref1/B | where z", "trigger": True},
                {"name": "B", "query": "@Y", "trigger": False},
            ],
        )
    )
    vega = make_vega(
        cells=[
            {"name": "B", "query": "@Y | where changed", "trigger": False},
            {"name": "trigger", "query": "@cells:ref1/B | where z", "trigger": True},
        ]
    )
    doc = yaml.safe_load(exported(vega, existing))
    assert [c["name"] for c in doc["cells"]] == ["trigger", "B"]
    assert doc["cells"][0]["query"] == "@cells:ref1/B | where z"
    assert doc["cells"][1] == {"name": "B", "query": "@Y | where changed", "trigger": False}


def test_single_cell_not_named_trigger_needs_cells_form():
    vega = make_vega(cells=[{"name": "Main", "query": "@X", "trigger": True}])
    doc = yaml.safe_load(exported(vega))
    assert doc["cells"] == [{"name": "Main", "query": "@X", "trigger": True}]


def test_text_fields_are_dropped_when_the_tenant_has_none():
    existing = yaml.safe_dump(make_yaml(logicDescription="old", attackScenario="old"))
    doc = yaml.safe_load(exported(make_vega(), existing))
    assert "logicDescription" not in doc and "attackScenario" not in doc


def test_tenant_detection_failing_the_lint_is_reported_as_such():
    vega = make_vega(lookBackSeconds=60, frequencyCron="@every 5m")
    doc = detection_file(vega, None, {})
    with pytest.raises(ExportError, match="does not pass this repository's validation"):
        verify_detection(render(doc, None, DETECTION_KEY_ORDER), vega, {})


def test_fresh_skill_file():
    vega = make_vega_skill(instructions="# Steps\n\nLook at the egress.")
    text = skill_file(vega, None)
    assert text == (
        "---\n"
        f'id: "{SKILL_ID}"\n'
        'name: "Service account sign-in triage"\n'
        'description: "Sign-ins by service accounts outside their fixed egress."\n'
        'type: "triage"\n'
        "---\n\n"
        "# Steps\n\nLook at the egress.\n"
    )
    verify_skill(text, vega, "skills/a/SKILL.md")


def test_skill_edit_touches_only_the_changed_fields():
    existing = "---\n" + f"id: {SKILL_ID}\n" + "name: Service account sign-in triage  # keep\n" + "description: Sign-ins by service accounts outside their fixed egress.\n" + "type: TRIAGE\n" + "---\n\n# Triage steps\n\nOld body.\n"
    vega = make_vega_skill(description="Rewritten in the UI", instructions="# Triage steps\n\nNew body.")
    text = skill_file(vega, existing)
    assert text == (
        "---\n"
        f"id: {SKILL_ID}\n"
        "name: Service account sign-in triage  # keep\n"
        "description: Rewritten in the UI\n"
        "type: TRIAGE\n"
        "---\n\n# Triage steps\n\nNew body.\n"
    )
    verify_skill(text, vega, "skills/a/SKILL.md")
    assert parse_skill(text, "x").external_id == SKILL_ID


def test_skill_body_is_kept_verbatim_when_only_the_frontmatter_changed():
    existing = make_skill_md(body="# Triage steps\n\n\nTwo blank lines above.\n")
    vega = make_vega_skill(name="Renamed", instructions="# Triage steps\n\n\nTwo blank lines above.")
    text = skill_file(vega, existing)
    assert text.endswith("---\n\n# Triage steps\n\n\nTwo blank lines above.\n")
    verify_skill(text, vega, "x")


def test_fresh_memory_file():
    vega = make_vega_memory(
        enabled=False,
        expiresAt="2027-01-31T00:00:00Z",
        labels=[{"id": MANAGED_LABEL_ID, "name": "detections-as-code"}, {"id": OTHER_LABEL_ID, "name": "Scanners"}],
    )
    text = render(memory_file(vega, None), None, MEMORY_KEY_ORDER)
    assert text == (
        'title: "Approved vulnerability scanner"\n'
        'description: "Weekly authenticated scans from scanner-01 are expected."\n'
        "content: |-\n"
        "  scanner-01 (192.0.2.10) runs authenticated scans every Sunday 02:00-06:00 UTC.\n"
        'status: "disabled"\n'
        'expiresAt: "2027-01-31"\n'
        "entities:\n"
        '  - type: "device"\n'
        '    value: "scanner-01"\n'
        '  - type: "ip"\n'
        '    value: "192.0.2.10"\n'
        "labels:\n"
        '  - "Scanners"\n'
    )
    verify_memory(text, vega, "m.yaml", LABEL_IDS, MANAGED_LABEL_ID)


def test_memory_edit_keeps_equivalent_values_and_the_managed_label_out():
    existing = (
        'title: "Approved vulnerability scanner"\n'
        "description: Weekly authenticated scans from scanner-01 are expected.\n"
        "content: |-\n"
        "  scanner-01 (192.0.2.10) runs authenticated scans every Sunday 02:00-06:00 UTC.\n"
        "expiresAt: 2027-01-31\n"
        "entities:\n"
        "  - {type: ip, value: 192.0.2.10}\n"
        "  - {type: device, value: scanner-01}\n"
        "labels: [scanners]\n"
    )
    vega = make_vega_memory(
        content="Changed in the UI.",
        expiresAt="2027-01-31T00:00:00Z",
        labels=[{"id": OTHER_LABEL_ID, "name": "Scanners"}, {"id": MANAGED_LABEL_ID, "name": "detections-as-code"}],
    )
    text = render(memory_file(vega, yaml.safe_load(existing)), existing, MEMORY_KEY_ORDER)
    assert text == (
        'title: "Approved vulnerability scanner"\n'
        "description: Weekly authenticated scans from scanner-01 are expected.\n"
        "content: |-\n"
        "  Changed in the UI.\n"
        "expiresAt: 2027-01-31\n"
        "entities:\n"
        "  - {type: ip, value: 192.0.2.10}\n"
        "  - {type: device, value: scanner-01}\n"
        "labels: [scanners]\n"
    )
    verify_memory(text, vega, "m.yaml", LABEL_IDS, MANAGED_LABEL_ID)


def test_memory_expiration_removed_in_the_ui_leaves_the_file():
    existing = yaml.safe_dump(make_memory_yaml(expiresAt="2027-01-31", status="enabled"))
    doc = memory_file(make_vega_memory(), yaml.safe_load(existing))
    assert "expiresAt" not in doc and doc["status"] == "enabled"
    spec = parse_memory(yaml.safe_load(render(doc, existing, MEMORY_KEY_ORDER)), "m")
    assert spec.expires_at is None


def test_slug():
    assert slug("Root Account Console Login!") == "root-account-console-login"
    assert slug("***") == ""
    assert len(slug("x" * 200)) == 80
