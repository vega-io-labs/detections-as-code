from __future__ import annotations

from typing import Any

import pytest
import yaml
from click.testing import CliRunner

from scripts import sync
from scripts.client import VegaAPIError
from scripts.reconciler import build_plan, execute_plan

from .conftest import SKILL_ID, make_skill_md, make_vega, make_vega_skill, make_yaml


class FakeClient:
    def __init__(self, fail: set[str] | None = None):
        self.fail = fail or set()
        self.calls: list[str] = []
        self.skills: list[dict[str, Any]] = []
        self.detections: list[dict[str, Any]] = [make_vega()]
        self.labels: list[dict[str, Any]] = []
        self.attached: list[tuple[list[str], list[str]]] = []
        self.skill_attached: list[tuple[list[str], list[str]]] = []

    def _step(self, op: str) -> None:
        self.calls.append(op)
        if op in self.fail:
            raise VegaAPIError(f"GraphQL request failed: {op} is down")

    def get_skills(self):
        self._step("get_skills")
        return self.skills

    def create_skills(self, entries):
        self._step("create_skills")
        self.skills = [{"id": "tenant-" + e["externalId"], "readOnly": False, **e} for e in entries]
        return {"results": [{"status": "VALID", "errors": []} for _ in entries]}

    def update_skills(self, entries):
        self._step("update_skills")
        return {"results": [{"status": "VALID", "errors": []} for _ in entries]}

    def delete_skills(self, ids):
        self._step("delete_skills")
        return {"results": [{"status": "VALID", "errors": []} for _ in ids]}

    def get_detections(self):
        self._step("get_detections")
        return self.detections

    def attach_skill_labels(self, skill_ids, label_ids):
        self._step("attach_skill_labels")
        self.skill_attached.append((skill_ids, label_ids))
        return {"objectIds": skill_ids}

    def attach_detection_labels(self, detection_ids, label_ids):
        self._step("attach_detection_labels")
        self.attached.append((detection_ids, label_ids))
        return {"objectIds": detection_ids}

    def create_detections(self, detections):
        self._step("create_detections")
        results = [{"status": "VALID", "detection": {"id": "new-" + d["externalId"]}} for d in detections]
        return {"results": results, "summary": {"committed": True}}

    def update_detections(self, detections):
        self._step("update_detections")
        ids = {d["externalId"]: d["id"] for d in self.detections}
        results = [{"status": "VALID", "detection": {"id": ids[d["externalId"]]}} for d in detections]
        return {"results": results, "summary": {"committed": True}}

    def get_memories(self):
        self._step("get_memories")
        return []

    def list_labels(self):
        self._step("list_labels")
        return self.labels

    def create_label(self, name, color):
        self._step("create_label")
        label = {"id": "label", "name": name}
        self.labels = [*self.labels, label]
        return label

    def create_memory(self, memory):
        self._step("create_memory")
        return {"vegaMemoryId": "MEM-NEW"}

    def update_memory(self, memory):
        self._step("update_memory")
        return {}

    def delete_memory(self, memory_id):
        self._step("delete_memory")
        return {}


@pytest.fixture
def repo(tmp_path):
    (tmp_path / "detections").mkdir()
    (tmp_path / "detections" / "d.yaml").write_text(yaml.safe_dump(make_yaml(skillIds=[SKILL_ID])))
    (tmp_path / "skills" / "a").mkdir(parents=True)
    (tmp_path / "skills" / "a" / "SKILL.md").write_text(make_skill_md())
    (tmp_path / "memories").mkdir()
    return tmp_path


def run(repo, client, monkeypatch, *extra):
    monkeypatch.setattr(sync.VegaClient, "login", classmethod(lambda cls, *a, **k: client))
    args = ["--detections-dir", str(repo / "detections"), "--skills-dir", str(repo / "skills"),
            "--memories-dir", str(repo / "memories"), "--access-key", "k", *extra]
    return CliRunner().invoke(sync.main, args)


def test_skill_then_detection_naming_it_in_one_run(repo, monkeypatch):
    client = FakeClient()
    result = run(repo, client, monkeypatch)
    assert result.exit_code == 0, result.output
    assert client.calls[:6] == [
        "get_skills", "create_skills", "get_skills",
        "list_labels", "create_label", "attach_skill_labels",
    ]
    assert client.calls[6] == "get_detections"
    assert "update_detections" in client.calls


def test_broken_detection_fails_before_any_write(repo, monkeypatch):
    (repo / "detections" / "bad.yaml").write_text(yaml.safe_dump(make_yaml(id="bad", severity=9)))
    client = FakeClient()
    result = run(repo, client, monkeypatch)
    assert result.exit_code != 0
    assert client.calls == []


def test_failure_after_skill_writes_still_reports_them(repo, monkeypatch):
    client = FakeClient(fail={"get_detections"})
    result = run(repo, client, monkeypatch)
    assert result.exit_code != 0
    assert "create_skills" in client.calls
    assert "detections: GraphQL request failed" in result.output
    assert "create_skills" in client.calls and "skill" in result.output


def test_memory_read_failure_does_not_stop_detections(repo, monkeypatch):
    client = FakeClient(fail={"list_labels"})
    result = run(repo, client, monkeypatch)
    assert result.exit_code == 1
    assert "update_detections" in client.calls
    assert "memories: GraphQL request failed: list_labels is down" in result.output


def test_skill_read_failure_holds_back_detections_naming_repo_skills(repo, monkeypatch):
    client = FakeClient(fail={"get_skills"})
    result = run(repo, client, monkeypatch)
    assert result.exit_code == 1
    assert "update_detections" not in client.calls
    assert "skills: GraphQL request failed: get_skills is down" in result.output


def test_skills_are_re_read_only_after_a_create(repo, monkeypatch):
    client = FakeClient()
    skill = make_vega_skill(externalId=SKILL_ID, description="changed in the UI")
    client.skills = [skill]
    result = run(repo, client, monkeypatch)
    assert result.exit_code == 0, result.output
    assert client.calls.count("get_skills") == 1
    assert "update_skills" in client.calls


def test_dry_run_writes_nothing_and_plans_new_skill_references(repo, monkeypatch):
    client = FakeClient()
    result = run(repo, client, monkeypatch, "--dry-run")
    assert result.exit_code == 0, result.output
    assert client.calls == ["get_skills", "get_detections", "get_memories", "list_labels"]
    assert "blocked:" not in result.output


def test_dry_run_holds_back_detections_naming_a_blocked_skill(repo, monkeypatch):
    client = FakeClient()
    client.skills = [make_vega_skill(id="ui", externalId=None)]
    result = run(repo, client, monkeypatch, "--dry-run")
    assert "not in the tenant" in result.output
    assert "create_skills" not in client.calls


def test_run_errors_land_in_the_step_summary(repo, monkeypatch, tmp_path):
    summary = tmp_path / "summary.md"
    monkeypatch.setenv("GITHUB_STEP_SUMMARY", str(summary))
    run(repo, FakeClient(fail={"get_detections"}), monkeypatch)
    text = summary.read_text()
    assert "Detection plan: not planned" in text
    assert "Run error: detections: GraphQL request failed" in text


def test_dry_run_with_blocked_entries_fails(repo, monkeypatch, tmp_path):
    summary = tmp_path / "summary.md"
    monkeypatch.setenv("GITHUB_STEP_SUMMARY", str(summary))
    client = FakeClient()
    client.skills = [make_vega_skill(id="ui", externalId=None)]
    result = run(repo, client, monkeypatch, "--dry-run")
    assert result.exit_code == 1, result.output
    assert "create_skills" not in client.calls
    text = summary.read_text()
    assert "dry run: 0 ok, 2 failed" in text and "Skill plan: creates=0 updates=0 deletes=0 blocked=1" in text


MANAGED = {"id": "managed-label", "name": "Managed by Git"}


def test_a_managed_detection_without_the_label_gets_it(repo, monkeypatch):
    client = FakeClient()
    client.labels = [MANAGED]
    result = run(repo, client, monkeypatch)
    assert result.exit_code == 0, result.output
    assert client.attached == [([make_vega()["id"]], ["managed-label"])]
    assert "create_label" not in client.calls


def test_the_label_is_created_when_the_tenant_has_none(repo, monkeypatch):
    client = FakeClient()
    result = run(repo, client, monkeypatch)
    assert result.exit_code == 0, result.output
    assert client.calls.count("create_label") == 1
    assert client.attached == [([make_vega()["id"]], ["label"])]


def test_labelling_needs_no_second_read_of_the_tenant(repo, monkeypatch):
    client = FakeClient()
    client.labels = [MANAGED]
    result = run(repo, client, monkeypatch)
    assert result.exit_code == 0, result.output
    assert client.calls.count("get_detections") == 1
    assert client.attached == [([make_vega()["id"]], ["managed-label"])]


def test_an_updated_detection_that_has_the_label_is_not_sent(repo, monkeypatch):
    client = FakeClient()
    client.labels = [MANAGED]
    client.detections = [make_vega(labels=[MANAGED])]
    result = run(repo, client, monkeypatch)
    assert result.exit_code == 0, result.output
    assert "update_detections" in client.calls
    assert "attach_detection_labels" not in client.calls

def test_a_new_detection_is_labelled_by_the_id_the_create_returned(repo, monkeypatch):
    (repo / "detections" / "n.yaml").write_text(yaml.safe_dump(make_yaml(id="brand-new", name="Brand new")))
    client = FakeClient()
    client.labels = [MANAGED]
    result = run(repo, client, monkeypatch)
    assert result.exit_code == 0, result.output
    assert "new-brand-new" in client.attached[0][0]

def test_an_already_labelled_detection_needs_no_label_call(repo, monkeypatch):
    (repo / "detections" / "d.yaml").write_text(yaml.safe_dump(make_yaml()))
    client = FakeClient()
    client.detections = [make_vega(labels=[{"id": "x", "name": "managed BY git"}])]
    result = run(repo, client, monkeypatch)
    assert result.exit_code == 0, result.output
    assert "attach_detection_labels" not in client.calls
    assert client.calls.count("get_detections") == 1


def test_a_detection_the_repo_does_not_manage_is_never_labelled(repo, monkeypatch):
    client = FakeClient()
    client.labels = [MANAGED]
    client.detections = [make_vega(), make_vega(id="ui", externalId="ui-made")]
    result = run(repo, client, monkeypatch, "--no-deletes")
    assert result.exit_code == 0, result.output
    assert client.attached == [([make_vega()["id"]], ["managed-label"])]


def test_a_label_failure_fails_the_run_but_keeps_the_writes(repo, monkeypatch):
    client = FakeClient(fail={"attach_detection_labels"})
    client.labels = [MANAGED]
    result = run(repo, client, monkeypatch)
    assert result.exit_code == 1
    assert "update_detections" in client.calls
    assert "failed=1" in result.output and "│ label " in result.output


def test_dry_run_says_which_detections_get_the_label(repo, monkeypatch):
    client = FakeClient()
    result = run(repo, client, monkeypatch, "--dry-run")
    assert result.exit_code == 0, result.output
    assert "1 detection(s) get the 'Managed by Git' label" in result.output
    assert "attach_detection_labels" not in client.calls


def test_a_created_skill_gets_the_label(repo, monkeypatch):
    client = FakeClient()
    client.labels = [MANAGED]
    result = run(repo, client, monkeypatch)
    assert result.exit_code == 0, result.output
    assert client.skill_attached == [(["tenant-" + SKILL_ID], ["managed-label"])]


def test_an_unchanged_skill_is_not_sent_again(repo, monkeypatch):
    client = FakeClient()
    client.labels = [MANAGED]
    client.skills = [make_vega_skill(externalId=SKILL_ID)]
    result = run(repo, client, monkeypatch)
    assert result.exit_code == 0, result.output
    assert "update_skills" not in client.calls and "create_skills" not in client.calls
    assert "attach_skill_labels" not in client.calls


def test_an_updated_skill_gets_it_and_a_ui_skill_never_does(repo, monkeypatch):
    client = FakeClient()
    client.labels = [MANAGED]
    client.skills = [
        make_vega_skill(externalId=SKILL_ID, description="changed in the UI"),
        make_vega_skill(id="ui", externalId=None, name="UI skill"),
    ]
    result = run(repo, client, monkeypatch)
    assert result.exit_code == 0, result.output
    assert client.skill_attached == [([client.skills[0]["id"]], ["managed-label"])]


def test_the_label_is_looked_up_once_per_run(repo, monkeypatch):
    client = FakeClient()
    client.labels = [MANAGED]
    run(repo, client, monkeypatch)
    assert client.skill_attached and client.attached
    assert client.calls.count("list_labels") == 2  # once for the label, once by the memory sync for file labels

def test_a_skill_label_failure_fails_the_run_but_keeps_detections(repo, monkeypatch):
    client = FakeClient(fail={"attach_skill_labels"})
    client.labels = [MANAGED]
    result = run(repo, client, monkeypatch)
    assert result.exit_code == 1
    assert "update_detections" in client.calls
    assert "skills: could not add the 'Managed by Git' label" in result.output


def test_dry_run_labels_no_skill(repo, monkeypatch):
    client = FakeClient()
    result = run(repo, client, monkeypatch, "--dry-run")
    assert result.exit_code == 0, result.output
    assert "attach_skill_labels" not in client.calls


KQL_ERROR = (
    "trigger cell query cannot be compiled: unknown query operator 'projct'\n"
    "   ╭─[ query:3:3 ]\n"
    " 3 │ | projct eventName, sourceIPAddress\n"
    "   │   ^^^^^^"
)


class RejectingClient(FakeClient):
    def __init__(self):
        super().__init__()
        self.detections = []

    def create_detections(self, detections):
        self._step("create_detections")
        results = [
            {"status": "INVALID", "errors": [{"code": "VALIDATION", "field": "cells", "message": KQL_ERROR}]}
            for _ in detections
        ]
        return {"results": results, "summary": {"committed": False}}


def test_a_rejected_test_mode_create_is_one_failure_with_the_full_error():
    client = RejectingClient()
    report = execute_plan(client, build_plan([make_yaml(state="test_mode")], []))

    assert [(r.kind, r.success) for r in report.results] == [("create", False)]
    assert "set_detections_state" not in client.calls
    details = sync._failure_details(report)
    assert "projct eventName, sourceIPAddress" in details
    assert "^^^^^^" in details
    assert "\n" not in sync._error_cell(report.results[0].error)
