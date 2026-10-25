from __future__ import annotations

from typing import Any

import pytest
import yaml
from click.testing import CliRunner

from scripts import sync
from scripts.client import VegaAPIError

from .conftest import SKILL_ID, make_skill_md, make_vega, make_vega_skill, make_yaml


class FakeClient:
    def __init__(self, fail: set[str] | None = None):
        self.fail = fail or set()
        self.calls: list[str] = []
        self.skills: list[dict[str, Any]] = []

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
        return [make_vega()]

    def create_detections(self, detections):
        self._step("create_detections")
        return {"results": [{"status": "VALID"} for _ in detections], "summary": {"committed": True}}

    def update_detections(self, detections):
        self._step("update_detections")
        return {"results": [{"status": "VALID"} for _ in detections], "summary": {"committed": True}}

    def get_memories(self):
        self._step("get_memories")
        return []

    def list_labels(self):
        self._step("list_labels")
        return []

    def create_label(self, name, color):
        self._step("create_label")
        return {"id": "label", "name": name}

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
    assert client.calls[:4] == ["get_skills", "create_skills", "get_skills", "get_detections"]
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
