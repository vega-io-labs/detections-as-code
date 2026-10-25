from __future__ import annotations

from typing import Any

import pytest

from scripts.client import VegaAPIError
from scripts.reconciler import build_plan
from scripts.skill_reconciler import (
    build_skill_plan,
    execute_skill_plan,
    hold_back_detections,
    load_skill_files,
    resolve_detection_skill_ids,
    skill_ids_by_external_id,
)
from scripts.skill_translator import parse_skill

from .conftest import (
    SKILL_ID,
    SKILL_TENANT_ID,
    YAML_ID,
    make_skill_md,
    make_vega,
    make_vega_skill,
    make_yaml,
)

OTHER_ID = "0c1d2e3f-4a5b-4c6d-8e7f-9a0b1c2d3e4f"


def spec(**overrides: Any):
    return parse_skill(make_skill_md(**overrides), "skills/a/SKILL.md")


def test_identical_skill_is_a_no_op():
    plan = build_skill_plan([spec()], [make_vega_skill()])
    assert plan.no_op_updates == 1
    assert not plan.creates and not plan.updates and not plan.deletes


def test_trailing_whitespace_in_the_tenant_does_not_diff():
    current = make_vega_skill(instructions=make_vega_skill()["instructions"] + "\n\n")
    assert build_skill_plan([spec()], [current]).no_op_updates == 1


@pytest.mark.parametrize(
    "overrides",
    [
        {"name": "Renamed"},
        {"description": "changed"},
        {"type": "investigation"},
        {"body": "# Different steps\n"},
    ],
)
def test_each_field_change_is_an_update(overrides):
    plan = build_skill_plan([spec(**overrides)], [make_vega_skill()])
    assert [(u.external_id, u.payload["id"]) for u in plan.updates] == [(SKILL_ID, SKILL_TENANT_ID)]


def test_rename_updates_in_place():
    plan = build_skill_plan([spec(name="Renamed")], [make_vega_skill()])
    assert len(plan.updates) == 1 and not plan.creates and not plan.deletes


def test_null_type_in_the_tenant_is_an_update():
    assert len(build_skill_plan([spec()], [make_vega_skill(type=None)]).updates) == 1


def test_new_file_is_a_create():
    plan = build_skill_plan([spec()], [])
    assert [s.external_id for s in plan.creates] == [SKILL_ID]


def test_managed_skill_without_a_file_is_deleted():
    plan = build_skill_plan([], [make_vega_skill()])
    assert [d.payload for d in plan.deletes] == [SKILL_TENANT_ID]


def test_ui_and_library_skills_are_never_touched():
    ui = make_vega_skill(id="ui", externalId=None, name="UI skill")
    library = make_vega_skill(id="lib", externalId=OTHER_ID, name="Library", readOnly=True)
    plan = build_skill_plan([], [ui, library])
    assert not plan.deletes and not plan.creates and not plan.updates


def test_new_file_named_like_a_ui_skill_is_blocked():
    ui = make_vega_skill(id="ui", externalId=None)
    plan = build_skill_plan([spec()], [ui])
    assert not plan.creates
    assert plan.blocked[0].kind == "create"
    assert "id ui" in plan.blocked[0].reason


def test_rename_onto_a_ui_skill_name_is_blocked():
    ui = make_vega_skill(id="ui", externalId=None, name="Taken")
    plan = build_skill_plan([spec(name="Taken")], [make_vega_skill(), ui])
    assert not plan.updates and plan.blocked[0].kind == "update"


def test_library_skill_with_the_same_name_does_not_block():
    library = make_vega_skill(id="lib", externalId=OTHER_ID, readOnly=True)
    assert len(build_skill_plan([spec()], [library]).creates) == 1


def test_name_freed_by_a_delete_in_the_same_run_is_not_blocked():
    leaving = make_vega_skill(id="old", externalId=OTHER_ID)
    plan = build_skill_plan([spec()], [leaving])
    assert [d.payload for d in plan.deletes] == ["old"]
    assert len(plan.creates) == 1 and not plan.blocked


def test_duplicate_ids_and_names_in_the_repo_are_rejected(tmp_path):
    for folder, skill_id, name in (("a", SKILL_ID, "A"), ("b", SKILL_ID, "B")):
        (tmp_path / folder).mkdir()
        (tmp_path / folder / "SKILL.md").write_text(make_skill_md(id=skill_id, name=name))
    with pytest.raises(ValueError, match="duplicate id"):
        load_skill_files([tmp_path])
    (tmp_path / "b" / "SKILL.md").write_text(make_skill_md(id=OTHER_ID, name="A"))
    with pytest.raises(ValueError, match="duplicate name"):
        load_skill_files([tmp_path])


def test_only_skill_md_files_are_read(tmp_path):
    (tmp_path / "a").mkdir()
    (tmp_path / "a" / "SKILL.md").write_text(make_skill_md())
    (tmp_path / "a" / "notes.md").write_text("not a skill")
    assert [s.external_id for s in load_skill_files([tmp_path])] == [SKILL_ID]


class FakeClient:
    def __init__(self, invalid=None, fail=None):
        self.invalid = invalid or set()
        self.fail = fail or set()
        self.calls: list[tuple[str, Any]] = []

    def _results(self, op, entries, key):
        self.calls.append((op, entries))
        if op in self.fail:
            raise VegaAPIError("GraphQL errors", [{"extensions": {"error_code_name": "ACCESS_DENIED"}}])
        out = []
        for e in entries:
            ident = e if isinstance(e, str) else e.get(key)
            if ident in self.invalid:
                out.append({"status": "INVALID", "errors": [{"code": "INVALID_FIELD", "field": "name", "message": "bad"}]})
            else:
                out.append({"status": "VALID", "errors": []})
        return {"results": out, "summary": {}}

    def create_skills(self, entries):
        return self._results("create", entries, "externalId")

    def update_skills(self, entries):
        return self._results("update", entries, "id")

    def delete_skills(self, ids):
        return self._results("delete", ids, "id")


def test_deletes_run_before_updates_and_creates():
    plan = build_skill_plan(
        [spec(body="# changed\n"), spec(id=OTHER_ID, name="New")],
        [make_vega_skill(), make_vega_skill(id="gone", externalId="1b2c3d4e-5f6a-4b7c-8d9e-0f1a2b3c4d5e", name="Gone")],
    )
    client = FakeClient()
    report = execute_skill_plan(client, plan)
    assert [c[0] for c in client.calls] == ["delete", "update", "create"]
    assert client.calls[0][1] == ["gone"]
    assert report.all_ok and all(r.target == "skill" for r in report.results)


def test_one_invalid_skill_does_not_fail_the_others():
    plan = build_skill_plan([spec(), spec(id=OTHER_ID, name="Other")], [])
    report = execute_skill_plan(FakeClient(invalid={OTHER_ID}), plan)
    assert [r.success for r in report.results] == [True, False]
    assert report.failed[0].error == "name: bad"


def test_batch_api_error_fails_every_entry_in_the_batch():
    plan = build_skill_plan([spec(), spec(id=OTHER_ID, name="Other")], [])
    report = execute_skill_plan(FakeClient(fail={"create"}), plan)
    assert len(report.failed) == 2
    assert all(r.error.startswith("batch API error") for r in report.failed)


def test_batches_of_one_hundred():
    specs = [
        spec(id=f"00000000-0000-4000-8000-{i:012d}", name=f"S{i}") for i in range(150)
    ]
    client = FakeClient()
    execute_skill_plan(client, build_skill_plan(specs, []))
    assert [len(entries) for _, entries in client.calls] == [100, 50]


def test_no_deletes_flag_and_blocked():
    plan = build_skill_plan([], [make_vega_skill()])
    client = FakeClient()
    assert execute_skill_plan(client, plan, skip_deletes=True).results == []
    assert client.calls == []
    blocked = build_skill_plan([spec()], [make_vega_skill(id="ui", externalId=None)])
    assert blocked.blocked and not blocked.creates
    assert execute_skill_plan(client, blocked).results == [] and client.calls == []


def test_repo_skill_ids_in_detections_resolve_to_tenant_ids():
    yamls = [make_yaml(skillIds=[SKILL_ID, "vega-skill", SKILL_TENANT_ID]), make_yaml(id="other")]
    resolved, unresolved = resolve_detection_skill_ids(
        yamls, [spec()], skill_ids_by_external_id([make_vega_skill()])
    )
    assert resolved[0]["skillIds"] == [SKILL_TENANT_ID, "vega-skill"]
    assert resolved[1] is yamls[1] and unresolved == {}
    assert yamls[0]["skillIds"][0] == SKILL_ID


def test_resolved_detection_with_the_skill_attached_is_a_no_op():
    yamls, _ = resolve_detection_skill_ids(
        [make_yaml(skillIds=[SKILL_ID])], [spec()], {SKILL_ID: SKILL_TENANT_ID}
    )
    plan = build_plan(yamls, [make_vega(skills=[{"id": SKILL_TENANT_ID}])])
    assert plan.no_op_updates == 1


def test_detection_naming_an_unsynced_skill_is_held_back():
    yamls, unresolved = resolve_detection_skill_ids(
        [make_yaml(skillIds=[SKILL_ID]), make_yaml(id="fine", name="Fine")], [spec()], {}
    )
    assert unresolved == {YAML_ID: [SKILL_ID]}
    plan = build_plan(yamls, [make_vega()])
    hold_back_detections(plan, unresolved)
    assert [b.external_id for b in plan.blocked] == [YAML_ID]
    assert plan.blocked[0].kind == "update" and SKILL_ID in plan.blocked[0].reason
    assert not plan.updates and [p.external_id for p in plan.creates] == ["fine"]
    assert not plan.deletes


def test_pr_lint_rejects_non_triage_repo_skills_on_any_detection(tmp_path, monkeypatch):
    from scripts.pr_validate import detection_skill_ref_checks, load_repo_skill_types

    monkeypatch.chdir(tmp_path)
    (tmp_path / "skills" / "t").mkdir(parents=True)
    (tmp_path / "skills" / "t" / "SKILL.md").write_text(make_skill_md(type="tuning"))
    (tmp_path / "detections").mkdir()
    (tmp_path / "detections" / "d.yaml").write_text(f"id: x\nskillIds: ['{SKILL_ID}']\n")
    checks = detection_skill_ref_checks(tmp_path / "detections", load_repo_skill_types(tmp_path / "skills"), {})
    assert [c.path for c in checks] == ["detections/d.yaml"]
    assert "only triage and investigation" in checks[0].schema_error


def test_pr_skill_checks(tmp_path, monkeypatch):
    from scripts.pr_validate import skill_repo_checks, skill_schema_check

    monkeypatch.chdir(tmp_path)
    root = tmp_path / "skills"
    for folder, skill_id in (("a", SKILL_ID), ("b", OTHER_ID)):
        (root / folder).mkdir(parents=True)
        (root / folder / "SKILL.md").write_text(make_skill_md(id=skill_id))
    (root / "c").mkdir()
    (root / "c" / "SKILL.md").write_text("broken")
    checks = skill_repo_checks(root, "HEAD")
    assert [c.path for c in checks] == ["skills/b/SKILL.md"]
    assert "duplicate name" in checks[0].schema_error

    (root / "a" / "skill.md").write_text("x")
    assert "exactly" in skill_schema_check(root / "a" / "skill.md").schema_error
    (root / "a" / "README.md").write_text("x")
    readme = skill_schema_check(root / "a" / "README.md")
    assert readme.schema_ok and "ignores it" in readme.warnings[0]
    assert not skill_schema_check(root / "c" / "SKILL.md").schema_ok


def _git(cwd, *args):
    import subprocess

    subprocess.run(["git", "-c", "user.email=t@t", "-c", "user.name=t", *args], cwd=cwd, check=True, capture_output=True)


@pytest.mark.parametrize(
    "change,flagged",
    [
        ("delete", True),
        ("change_id", True),
        ("move_and_change_id", True),
        ("move", False),
        ("edit_body", False),
        ("retype_to_tuning", True),
    ],
)
def test_pr_lint_catches_skills_removed_or_retyped_under_an_unchanged_detection(tmp_path, monkeypatch, change, flagged):
    import shutil

    from scripts.pr_validate import detection_skill_ref_checks, load_repo_skill_types, skill_ids_at

    monkeypatch.chdir(tmp_path)
    _git(tmp_path, "init", "-q")
    (tmp_path / "skills" / "a").mkdir(parents=True)
    (tmp_path / "skills" / "a" / "SKILL.md").write_text(make_skill_md())
    (tmp_path / "detections").mkdir()
    (tmp_path / "detections" / "d.yaml").write_text(f"id: x\nskillIds: ['{SKILL_ID}']\n")
    _git(tmp_path, "add", "-A")
    _git(tmp_path, "commit", "-qm", "base")
    skill = tmp_path / "skills" / "a" / "SKILL.md"
    if change == "delete":
        shutil.rmtree(tmp_path / "skills" / "a")
    elif change == "change_id":
        skill.write_text(make_skill_md(id=OTHER_ID))
    elif change in ("move", "move_and_change_id"):
        (tmp_path / "skills" / "b").mkdir()
        (tmp_path / "skills" / "b" / "SKILL.md").write_text(
            make_skill_md(id=OTHER_ID if change == "move_and_change_id" else SKILL_ID)
        )
        shutil.rmtree(tmp_path / "skills" / "a")
    elif change == "edit_body":
        skill.write_text(make_skill_md(body="# New steps\n"))
    elif change == "retype_to_tuning":
        skill.write_text(make_skill_md(type="tuning"))

    types = load_repo_skill_types(tmp_path / "skills")
    removed = {s: p for s, p in skill_ids_at("HEAD", tmp_path / "skills").items() if s not in types}
    checks = detection_skill_ref_checks(tmp_path / "detections", types, removed)
    assert bool(checks) is flagged


def test_hold_back_matches_a_detection_id_with_surrounding_spaces():
    yamls, unresolved = resolve_detection_skill_ids(
        [make_yaml(id=f"  {YAML_ID} ", skillIds=[SKILL_ID])], [spec()], {}
    )
    assert unresolved == {YAML_ID: [SKILL_ID]}
    plan = build_plan(yamls, [make_vega()])
    hold_back_detections(plan, unresolved)
    assert len(plan.blocked) == 1 and not plan.updates


def test_two_repo_skills_can_swap_names():
    one = make_vega_skill(id="t1", externalId=SKILL_ID, name="One")
    two = make_vega_skill(id="t2", externalId=OTHER_ID, name="Two")
    plan = build_skill_plan([spec(name="Two"), spec(id=OTHER_ID, name="One")], [one, two])
    assert not plan.blocked and len(plan.updates) == 2


def test_new_skill_taking_a_name_another_repo_skill_gives_up_waits():
    two = make_vega_skill(id="t2", externalId=OTHER_ID, name="Old")
    plan = build_skill_plan([spec(id=OTHER_ID, name="New"), spec(name="Old")], [two])
    assert len(plan.updates) == 1
    assert plan.blocked[0].kind == "create" and "Merge the rename first" in plan.blocked[0].reason


def test_pr_lint_of_a_skills_only_repo_without_detections(tmp_path, monkeypatch):
    import subprocess
    import sys

    from scripts import pr_validate

    def git(*args):
        subprocess.run(["git", "-c", "user.email=t@t", "-c", "user.name=t", *args], cwd=tmp_path, check=True, capture_output=True)

    monkeypatch.chdir(tmp_path)
    git("init", "-q")
    git("commit", "-q", "--allow-empty", "-m", "base")
    (tmp_path / "skills" / "a").mkdir(parents=True)
    (tmp_path / "skills" / "a" / "SKILL.md").write_text(make_skill_md())
    git("add", "-A")
    git("commit", "-qm", "add skill")
    monkeypatch.setattr(sys, "argv", ["pr_validate", "--base-sha", "HEAD~1"])
    assert pr_validate.main() == 0
