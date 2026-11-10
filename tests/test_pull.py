from __future__ import annotations

from typing import Any

import pytest
import yaml
from click.testing import CliRunner

from scripts import pull
from scripts.client import VegaAPIError
from scripts.pull import pull_detections, pull_memories, pull_skills
from scripts.memory_reconciler import MemoryState

from .conftest import (
    LABELS,
    SKILL_ID,
    SKILL_TENANT_ID,
    YAML_ID,
    make_memory_yaml,
    make_skill_md,
    make_vega,
    make_vega_memory,
    make_vega_skill,
    make_yaml,
)

NEW_ID = "7d0c7a8e-1c2b-4d3e-9f10-bbbbbbbbbbbb"


class FakeClient:
    def __init__(self, fail: set[str] | None = None):
        self.fail = fail or set()
        self.calls: list[str] = []
        self.detections: list[dict[str, Any]] = [make_vega()]
        self.skills: list[dict[str, Any]] = [make_vega_skill()]
        self.memories: list[dict[str, Any]] = [make_vega_memory()]
        self.labels: list[dict[str, Any]] = list(LABELS)

    def _step(self, op: str) -> None:
        self.calls.append(op)
        if op in self.fail:
            raise VegaAPIError(f"GraphQL request failed: {op} is down")

    def get_detections(self):
        self._step("get_detections")
        return self.detections

    def get_skills(self):
        self._step("get_skills")
        return self.skills

    def get_memories(self):
        self._step("get_memories")
        return self.memories

    def list_labels(self):
        self._step("list_labels")
        return self.labels


@pytest.fixture
def repo(tmp_path):
    (tmp_path / "detections").mkdir()
    (tmp_path / "detections" / "root-login.yaml").write_text(yaml.safe_dump(make_yaml()))
    (tmp_path / "skills" / "triage" / "service-account").mkdir(parents=True)
    (tmp_path / "skills" / "triage" / "service-account" / "SKILL.md").write_text(make_skill_md())
    (tmp_path / "skills" / "triage" / "service-account" / "reference.md").write_text("# notes\n")
    (tmp_path / "memories").mkdir()
    (tmp_path / "memories" / "scanner.yaml").write_text(yaml.safe_dump(make_memory_yaml()))
    return tmp_path


def run(repo, client, monkeypatch, *extra, skills="skills"):
    monkeypatch.setattr(pull.VegaClient, "login", classmethod(lambda cls, *a, **k: client))
    args = ["--detections-dir", str(repo / "detections"), "--skills-dir", str(repo / skills),
            "--memories-dir", str(repo / "memories"), "--access-key", "k", *extra]
    return CliRunner().invoke(pull.main, args)


def dirs(repo, name):
    return ((repo / name).resolve(),)


# ---- detections --------------------------------------------------------------


def test_matching_detection_files_produce_no_change(repo):
    assert pull_detections(dirs(repo, "detections"), [make_vega()], {}) == ([], [])


def test_a_detection_failing_the_lint_is_a_note_and_the_rest_is_pulled(repo):
    bad = make_vega(id="bad", externalId=NEW_ID, name="x" * 230)
    changes, notes = pull_detections(dirs(repo, "detections"), [make_vega(severity="LOW"), bad], {})
    assert [c.action for c in changes] == ["update"]
    assert len(notes) == 1 and "does not pass this repository's validation" in notes[0]


def test_ui_edit_becomes_a_file_update(repo):
    changes, _ = pull_detections(dirs(repo, "detections"), [make_vega(severity="LOW", lookBackSeconds=600)], {})
    assert [(c.action, c.path.name, c.detail) for c in changes] == [
        ("update", "root-login.yaml", "severity, lookBackSeconds")
    ]
    assert yaml.safe_load(changes[0].text)["severity"] == 1


def test_ui_created_detection_becomes_a_new_file_named_after_it(repo):
    new = make_vega(id="new", externalId=NEW_ID, name="Tor Network Login!")
    changes, _ = pull_detections(dirs(repo, "detections"), [make_vega(), new], {})
    assert [(c.action, str(c.path.relative_to(repo))) for c in changes] == [
        ("add", "detections/tor-network-login.yaml")
    ]
    assert yaml.safe_load(changes[0].text)["id"] == NEW_ID


def test_new_file_name_avoids_an_existing_file(repo):
    new = make_vega(id="new", externalId=NEW_ID, name="Root login")
    changes, _ = pull_detections(dirs(repo, "detections"), [make_vega(), new], {})
    assert changes[0].path.name == f"root-login-{NEW_ID[:8]}.yaml"


def test_detection_deleted_in_the_ui_removes_the_file(repo):
    changes, _ = pull_detections(dirs(repo, "detections"), [], {})
    assert [(c.action, c.path.name, c.external_id) for c in changes] == [
        ("remove", "root-login.yaml", YAML_ID)
    ]
    assert changes[0].text is None


def test_library_detections_are_not_pulled(repo):
    library = make_vega(id="lib", externalId="lib", createdBy={"principalType": "vega_library"})
    assert pull_detections(dirs(repo, "detections"), [make_vega(), library], {}) == ([], [])


def test_skill_ids_use_the_repository_id_when_skills_are_managed(repo):
    vega = make_vega(skills=[{"id": SKILL_TENANT_ID}])
    managed, _ = pull_detections(dirs(repo, "detections"), [vega], {SKILL_ID: SKILL_TENANT_ID})
    assert yaml.safe_load(managed[0].text)["skillIds"] == [SKILL_ID]
    unmanaged, _ = pull_detections(dirs(repo, "detections"), [vega], None)
    assert yaml.safe_load(unmanaged[0].text)["skillIds"] == [SKILL_TENANT_ID]


# ---- skills ------------------------------------------------------------------


def test_matching_skill_files_produce_no_change(repo):
    assert pull_skills(dirs(repo, "skills"), [make_vega_skill()]) == ([], [])


def test_skill_edit_add_and_delete(repo):
    edited = make_vega_skill(instructions="# Triage steps\n\nChanged.")
    new = make_vega_skill(id="t2", externalId="9b0f5a3e-2c4d-4e6f-9a1b-3c5d7e9f1a2c", name="Lateral movement")
    ui_made = make_vega_skill(id="ui", externalId=None, name="From the UI")
    library = make_vega_skill(id="lib", externalId="lib", readOnly=True)
    changes, _ = pull_skills(dirs(repo, "skills"), [edited, new, ui_made, library])
    assert [(c.action, str(c.path.relative_to(repo)), c.detail) for c in changes] == [
        ("update", "skills/triage/service-account/SKILL.md", "instructions"),
        ("add", "skills/lateral-movement/SKILL.md", ""),
    ]
    assert pull_skills(dirs(repo, "skills"), [ui_made, library]) == ([
        pull.Change("skill", "remove", repo / "skills" / "triage" / "service-account" / "SKILL.md", SKILL_ID, "Service account sign-in triage")
    ], [])


# ---- memories ----------------------------------------------------------------


def state(memories, labels=LABELS):
    return MemoryState(memories=memories, labels=labels)


def test_matching_memory_files_produce_no_change(repo):
    assert pull_memories(dirs(repo, "memories"), state([make_vega_memory()])) == ([], [])


def test_memory_edit_add_and_delete(repo):
    edited = make_vega_memory(content="Changed in the UI")
    new = make_vega_memory(id="m2", vegaMemoryId="MEM-NEW", title="Payroll server owner")
    unmanaged = make_vega_memory(id="m3", title="From the UI", labels=[])
    changes, notes = pull_memories(dirs(repo, "memories"), state([edited, new, unmanaged]))
    assert notes == []
    assert [(c.action, str(c.path.relative_to(repo)), c.external_id, c.detail) for c in changes] == [
        ("update", "memories/scanner.yaml", "MEM-K7QX2", "content"),
        ("add", "memories/payroll-server-owner.yaml", "MEM-NEW", ""),
    ]
    changes, _ = pull_memories(dirs(repo, "memories"), state([unmanaged]))
    assert [(c.action, c.name) for c in changes] == [("remove", "Approved vulnerability scanner")]


def test_memory_file_matching_an_unmanaged_memory_is_left_in_place(repo):
    released = make_vega_memory(labels=[])
    changes, notes = pull_memories(dirs(repo, "memories"), state([released]))
    assert changes == []
    assert len(notes) == 1 and "left in place" in notes[0]


def test_memories_are_not_pulled_before_the_label_exists(repo):
    changes, notes = pull_memories(dirs(repo, "memories"), state([make_vega_memory(labels=[])], labels=[]))
    assert changes == []
    assert "label does not exist" in notes[0]


# ---- the command -------------------------------------------------------------


def test_pull_writes_every_kind_and_the_pr_body(repo, monkeypatch, tmp_path):
    client = FakeClient()
    client.detections = [make_vega(name="Renamed"), make_vega(id="n", externalId=NEW_ID, name="New one")]
    client.skills = []
    client.memories = [make_vega_memory(content="Changed")]
    body = tmp_path / "body.md"
    result = run(repo, client, monkeypatch, "--pr-body-file", str(body))
    assert result.exit_code == 0, result.output
    assert client.calls == ["get_skills", "get_detections", "get_memories", "list_labels"]
    assert yaml.safe_load((repo / "detections" / "root-login.yaml").read_text())["name"] == "Renamed"
    assert (repo / "detections" / "new-one.yaml").exists()
    assert not (repo / "skills" / "triage").exists(), "the whole skill folder goes, parents pruned"
    assert (repo / "skills").exists()
    assert yaml.safe_load((repo / "memories" / "scanner.yaml").read_text())["content"] == "Changed"
    text = body.read_text()
    assert "| detection | update | `" + YAML_ID + "` | Renamed | name |" in text
    assert "| detection | add | `" + NEW_ID + "` | New one | " in text
    assert "| skill | remove | `" + SKILL_ID + "` |" in text
    assert "| memory | update | `MEM-K7QX2` |" in text
    assert "Sync ALL" in text


def snapshot(repo):
    return {p: p.read_text() for p in repo.rglob("*") if p.is_file() and p.suffix in (".yaml", ".md")}


def test_nothing_to_pull_writes_nothing(repo, monkeypatch, tmp_path):
    body = tmp_path / "body.txt"
    before = snapshot(repo)
    result = run(repo, FakeClient(), monkeypatch, "--pr-body-file", str(body))
    assert result.exit_code == 0, result.output
    assert "already matches" in result.output
    assert snapshot(repo) == before
    assert body.exists()


def test_dry_run_writes_nothing(repo, monkeypatch):
    client = FakeClient()
    client.detections = []
    result = run(repo, client, monkeypatch, "--dry-run")
    assert result.exit_code == 0, result.output
    assert (repo / "detections" / "root-login.yaml").exists()
    assert "remove" in result.output


def test_a_failed_read_writes_nothing_and_fails(repo, monkeypatch, tmp_path):
    client = FakeClient(fail={"get_memories"})
    client.detections = []
    summary = tmp_path / "summary.md"
    monkeypatch.setenv("GITHUB_STEP_SUMMARY", str(summary))
    result = run(repo, client, monkeypatch)
    assert result.exit_code == 1
    assert (repo / "detections" / "root-login.yaml").exists()
    assert "memories: GraphQL request failed: get_memories is down" in result.output
    assert "Run error: memories" in summary.read_text()


def test_skills_read_failure_holds_back_detections(repo, monkeypatch):
    client = FakeClient(fail={"get_skills"})
    result = run(repo, client, monkeypatch)
    assert result.exit_code == 1
    assert "get_detections" not in client.calls
    assert "detections: not pulled" in result.output


def test_without_a_skills_folder_detections_keep_tenant_skill_ids(repo, monkeypatch):
    client = FakeClient()
    client.detections = [make_vega(skills=[{"id": SKILL_TENANT_ID}])]
    result = run(repo, client, monkeypatch, skills="no-skills")
    assert result.exit_code == 0, result.output
    assert "get_skills" not in client.calls
    assert yaml.safe_load((repo / "detections" / "root-login.yaml").read_text())["skillIds"] == [SKILL_TENANT_ID]


def test_memories_unavailable_is_a_note_not_an_error(repo, monkeypatch):
    class Denied(FakeClient):
        def get_memories(self):
            self.calls.append("get_memories")
            raise VegaAPIError("denied", [{"extensions": {"error_code_name": "ACCESS_DENIED"}}])

    result = run(repo, Denied(), monkeypatch)
    assert result.exit_code == 0, result.output
    assert "Memories were not pulled" in result.output


def test_an_unpullable_object_is_a_note_and_the_rest_is_still_written(repo, monkeypatch, tmp_path):
    client = FakeClient()
    client.detections = [make_vega(name="Renamed"), make_vega(id="bad", externalId=NEW_ID, name="x" * 230)]
    body = tmp_path / "body.txt"
    monkeypatch.setenv("GITHUB_ACTIONS", "true")
    result = run(repo, client, monkeypatch, "--pr-body-file", str(body))
    assert result.exit_code == 0, result.output
    assert yaml.safe_load((repo / "detections" / "root-login.yaml").read_text())["name"] == "Renamed"
    assert "::warning::Detection " in result.output
    assert "**Not pulled**" in body.read_text() and "does not pass this repository's validation" in body.read_text()


def test_removing_a_skill_takes_its_folder_but_never_the_root(repo, monkeypatch):
    (repo / "skills" / "SKILL.md").write_text(make_skill_md(id="9b0f5a3e-2c4d-4e6f-9a1b-3c5d7e9f1a2c", name="Root skill"))
    client = FakeClient()
    client.skills = []
    result = run(repo, client, monkeypatch)
    assert result.exit_code == 0, result.output
    assert not (repo / "skills" / "triage").exists()
    assert (repo / "skills").is_dir() and not (repo / "skills" / "SKILL.md").exists()
