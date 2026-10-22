"""PR-time validator: schema lint for changed detections, skills and memories.

KQL validation is deliberately not done at PR time. The sync workflow's
createDetections/updateDetections calls validate KQL server-side on merge,
and any failure is reported in that run's step summary. Running a pre-flight
runFederatedQuery here would duplicate that check, cost tenant compute, and
introduce edge cases around multi-cell reference resolution that only the
deployment path resolves correctly.

Usage (in GitHub Actions):
  python -m scripts.pr_validate \
    --base-sha "$BASE_SHA" \
    --detections-dir ./detections \
    --skills-dir ./skills \
    --memories-dir ./memories

No tenant secret is required. Schema validation is pure YAML parsing.
"""

from __future__ import annotations

import argparse
import io
import os
import subprocess
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable

import yaml
from rich.console import Console
from rich.table import Table

from .consts import (
    DETECTION_SKILL_TYPES,
    MEMORY_TENANT_MAX_ACTIVE,
    SKILL_FILE_NAME,
    MemoryStatus,
    SkillType,
)
from .memory_translator import MemorySpec, memory_warnings, parse_memory
from .skill_translator import parse_skill
from .translator import create_only_warnings, yaml_to_create_input
from .utils import yaml_files

console = Console()

_STEP_SUMMARY_WIDTH = 160


@dataclass
class FileCheck:
    path: str
    schema_ok: bool
    schema_error: str | None = None
    # Surfaced, never fatal. For detections these are the rules that only
    # bind when the detection is new: the check runs without tenant access and
    # cannot tell a create from an update.
    warnings: list[str] = field(default_factory=list)


@dataclass
class Report:
    checks: list[FileCheck] = field(default_factory=list)

    def add(self, check: FileCheck) -> None:
        for existing in self.checks:
            if existing.path == check.path:
                errors = [
                    e for e in (existing.schema_error, check.schema_error) if e
                ]
                existing.schema_ok = existing.schema_ok and check.schema_ok
                existing.schema_error = "; ".join(errors) or None
                existing.warnings.extend(check.warnings)
                return
        self.checks.append(check)

    @property
    def all_ok(self) -> bool:
        return all(c.schema_ok for c in self.checks)

    @property
    def warned(self) -> list[FileCheck]:
        return [c for c in self.checks if c.warnings]


def _is_yaml(path: str) -> bool:
    return path.endswith(".yaml") or path.endswith(".yml")


def _is_markdown(path: str) -> bool:
    return path.lower().endswith(".md")


def _is_skill_file(path: str) -> bool:
    return Path(path).name == SKILL_FILE_NAME


def changed_paths(
    base_sha: str,
    directory: Path,
    match: Callable[[str], bool] = _is_yaml,
) -> tuple[list[Path], list[str]]:
    rel = directory.relative_to(Path.cwd())
    cmd = [
        "git",
        "diff",
        "--name-status",
        f"{base_sha}...HEAD",
        "--",
        str(rel),
    ]
    out = subprocess.check_output(cmd, text=True).strip()
    edited: list[Path] = []
    deleted: list[str] = []
    for line in out.splitlines():
        if not line:
            continue
        parts = line.split("\t")
        status, paths = parts[0], parts[1:]
        path = paths[-1]
        if not match(path):
            continue
        if status.startswith("D"):
            deleted.append(path)
        else:
            edited.append(Path(path))
    return edited, deleted


def schema_check(file_path: Path) -> FileCheck:
    check = FileCheck(path=str(file_path), schema_ok=False)
    try:
        doc = yaml.safe_load(file_path.read_text())
    except yaml.YAMLError as e:
        check.schema_error = f"YAML parse: {e}"
        return check
    if doc is None:
        check.schema_error = "empty file"
        return check
    try:
        yaml_to_create_input(doc)
        check.schema_ok = True
        check.warnings = create_only_warnings(doc)
    except (ValueError, KeyError) as e:
        check.schema_error = str(e)
    return check


def skill_schema_check(file_path: Path) -> FileCheck:
    check = FileCheck(path=str(file_path), schema_ok=False)
    if file_path.name != SKILL_FILE_NAME:
        if file_path.name.lower() == SKILL_FILE_NAME.lower():
            check.schema_error = (
                f"name the file {SKILL_FILE_NAME} exactly; the sync reads "
                f"only files with that name"
            )
        else:
            check.schema_ok = True
            check.warnings = [
                f"not a {SKILL_FILE_NAME}, so the sync ignores it. A skill is "
                f"the {SKILL_FILE_NAME} body alone; extra files are not "
                f"uploaded"
            ]
        return check
    try:
        parse_skill(file_path.read_text(encoding="utf-8"), str(file_path))
    except ValueError as e:
        check.schema_error = str(e)
        return check
    check.schema_ok = True
    return check


def load_repo_skill_types(skills_dir: Path) -> dict[str, SkillType]:
    types: dict[str, SkillType] = {}
    if not skills_dir.exists():
        return types
    for f in sorted(skills_dir.glob(f"**/{SKILL_FILE_NAME}")):
        try:
            spec = parse_skill(f.read_text(encoding="utf-8"), str(f))
        except ValueError:
            continue
        types[spec.external_id] = spec.type
    return types


def skill_ids_at(rev: str, skills_dir: Path) -> dict[str, str]:
    rel = str(skills_dir.relative_to(Path.cwd()))
    listing = subprocess.check_output(
        ["git", "ls-tree", "-r", "--name-only", rev, "--", rel], text=True
    )
    ids: dict[str, str] = {}
    for path in listing.splitlines():
        if Path(path).name != SKILL_FILE_NAME:
            continue
        try:
            raw = subprocess.check_output(["git", "show", f"{rev}:{path}"], text=True)
            ids[parse_skill(raw, path).external_id] = path
        except (subprocess.CalledProcessError, ValueError):
            continue
    return ids


def detection_skill_ref_checks(
    detections_dir: Path,
    repo_skill_types: dict[str, SkillType],
    removed: dict[str, str],
) -> list[FileCheck]:
    # Every detection is checked, not only the changed ones: the PR that
    # breaks a detection is often the one changing a skill it names. A skill
    # whose id disappears (file deleted, id changed) is deleted by the sync
    # before detections run, so a detection still naming it fails at merge.
    checks: list[FileCheck] = []
    for f in yaml_files(detections_dir):
        try:
            doc = yaml.safe_load(f.read_text())
        except yaml.YAMLError:
            continue
        if not isinstance(doc, dict):
            continue
        problems: list[str] = []
        for i, value in enumerate(doc.get("skillIds") or []):
            value = str(value).strip()
            skill_type = repo_skill_types.get(value)
            if skill_type is not None and skill_type not in DETECTION_SKILL_TYPES:
                problems.append(
                    f"'skillIds[{i}]' is the {skill_type.value} skill {value!r} "
                    f"from skills/; only triage and investigation skills can be "
                    f"attached to a detection"
                )
            elif value in removed:
                problems.append(
                    f"'skillIds[{i}]' names skill {value!r}, which this PR "
                    f"removes from {removed[value]} (file deleted or id "
                    f"changed). Remove it from skillIds in the same PR"
                )
        if problems:
            checks.append(
                FileCheck(
                    path=str(f.relative_to(Path.cwd())),
                    schema_ok=False,
                    schema_error="; ".join(problems),
                )
            )
    return checks


def skill_repo_checks(skills_dir: Path) -> list[FileCheck]:
    # The id is the identity of a skill, and createSkills matches an existing
    # skill by name, so two files sharing either would end up as one skill.
    # Both are checked across the whole folder, not only the changed files.
    checks: list[FileCheck] = []
    first_by_id: dict[str, str] = {}
    first_by_name: dict[str, str] = {}
    for f in sorted(skills_dir.glob(f"**/{SKILL_FILE_NAME}")):
        rel = str(f.relative_to(Path.cwd()))
        try:
            spec = parse_skill(f.read_text(encoding="utf-8"), rel)
        except ValueError:
            continue
        for key, first, what in (
            (spec.external_id, first_by_id, "id"),
            (spec.name, first_by_name, "name"),
        ):
            if key in first:
                checks.append(
                    FileCheck(
                        path=rel,
                        schema_ok=False,
                        schema_error=(
                            f"duplicate {what} {key!r} (also in {first[key]})"
                        ),
                    )
                )
            else:
                first[key] = rel
    return checks


def memory_schema_check(file_path: Path) -> FileCheck:
    check = FileCheck(path=str(file_path), schema_ok=False)
    try:
        doc = yaml.safe_load(file_path.read_text())
    except yaml.YAMLError as e:
        check.schema_error = f"YAML parse: {e}"
        return check
    if doc is None:
        check.schema_error = "empty file"
        return check
    try:
        spec = parse_memory(doc, str(file_path))
    except ValueError as e:
        check.schema_error = str(e)
        return check
    check.schema_ok = True
    check.warnings = memory_warnings(spec)
    return check


def _parse_memory_text(text: str, where: str) -> MemorySpec | None:
    try:
        doc = yaml.safe_load(text)
        return None if doc is None else parse_memory(doc, where)
    except (ValueError, yaml.YAMLError):
        return None


def memory_title_change_checks(
    memories_dir: Path, base_sha: str
) -> list[FileCheck]:
    # The title is the identity of a memory, so changing it is a delete plus a
    # create: the memory gets a new MEM- id and loses its usage history.
    rel = str(memories_dir.relative_to(Path.cwd()))
    out = subprocess.check_output(
        ["git", "diff", "--name-status", "-M", f"{base_sha}...HEAD", "--", rel],
        text=True,
    )
    checks: list[FileCheck] = []
    for line in out.splitlines():
        status, *paths = line.split("\t")
        if not status.startswith(("M", "R")) or not _is_yaml(paths[-1]):
            continue
        old_path, new_path = paths[0], paths[-1]
        try:
            old_text = subprocess.check_output(
                ["git", "show", f"{base_sha}:{old_path}"], text=True
            )
        except subprocess.CalledProcessError:
            continue
        old = _parse_memory_text(old_text, old_path)
        new = _parse_memory_text(Path(new_path).read_text(), new_path)
        if old is None or new is None or old.title == new.title:
            continue
        checks.append(
            FileCheck(
                path=new_path,
                schema_ok=True,
                warnings=[
                    f"title changed from {old.title!r} to {new.title!r}. The "
                    f"title is the identity, so the sync deletes the memory "
                    f"and creates a new one with a new MEM- id and no usage "
                    f"history"
                ],
            )
        )
    return checks


def memory_repo_checks(memories_dir: Path) -> list[FileCheck]:
    # Titles are the identity of a memory and the tenant caps active memories,
    # so both have to be checked across the whole folder, not only the files
    # a PR touched. A file that does not parse is already reported on its own.
    checks: list[FileCheck] = []
    first_file_by_title: dict[str, str] = {}
    active = 0
    for f in yaml_files(memories_dir):
        rel = str(f.relative_to(Path.cwd()))
        spec = _parse_memory_text(f.read_text(), rel)
        if spec is None:
            continue
        if spec.status == MemoryStatus.ENABLED:
            active += 1
        if spec.title in first_file_by_title:
            checks.append(
                FileCheck(
                    path=rel,
                    schema_ok=False,
                    schema_error=(
                        f"duplicate title {spec.title!r} (also in "
                        f"{first_file_by_title[spec.title]}). The title links "
                        f"a file to its memory, so it must be unique"
                    ),
                )
            )
        else:
            first_file_by_title[spec.title] = rel
    if active > MEMORY_TENANT_MAX_ACTIVE:
        checks.append(
            FileCheck(
                path=str(memories_dir.relative_to(Path.cwd())),
                schema_ok=False,
                schema_error=(
                    f"{active} enabled memories; a tenant holds at most "
                    f"{MEMORY_TENANT_MAX_ACTIVE} active memories, including "
                    f"the ones written in the UI and the ones Vega learns"
                ),
            )
        )
    return checks


@dataclass(frozen=True)
class Kind:
    name: str
    dir: Path
    match: Callable[[str], bool]
    synced: Callable[[str], bool]
    schema_check: Callable[[Path], FileCheck]
    repo_checks: Callable[[Path, str], list[FileCheck]]


def _no_repo_checks(directory: Path, base_sha: str) -> list[FileCheck]:
    return []


def _skill_repo_checks(directory: Path, base_sha: str) -> list[FileCheck]:
    return skill_repo_checks(directory)


def _memory_repo_checks(directory: Path, base_sha: str) -> list[FileCheck]:
    return [
        *memory_title_change_checks(directory, base_sha),
        *memory_repo_checks(directory),
    ]


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Validate detection, skill and memory files in a PR."
    )
    parser.add_argument("--base-sha", required=True)
    parser.add_argument("--detections-dir", default="./detections")
    parser.add_argument("--skills-dir", default="./skills")
    parser.add_argument("--memories-dir", default="./memories")
    args = parser.parse_args()

    detections_dir = Path(args.detections_dir).resolve()
    skills_dir = Path(args.skills_dir).resolve()
    kinds = (
        Kind(
            name="detections",
            dir=detections_dir,
            match=_is_yaml,
            synced=_is_yaml,
            schema_check=schema_check,
            repo_checks=_no_repo_checks,
        ),
        Kind(
            name="skills",
            dir=skills_dir,
            match=_is_markdown,
            synced=_is_skill_file,
            schema_check=skill_schema_check,
            repo_checks=_skill_repo_checks,
        ),
        Kind(
            name="memories",
            dir=Path(args.memories_dir).resolve(),
            match=_is_yaml,
            synced=_is_yaml,
            schema_check=memory_schema_check,
            repo_checks=_memory_repo_checks,
        ),
    )

    report = Report()
    edited_count = 0
    deleted: list[str] = []
    edited_kinds: set[str] = set()
    changed_kinds: set[str] = set()
    for kind in kinds:
        if not kind.dir.exists():
            continue
        edited, removed = changed_paths(args.base_sha, kind.dir, kind.match)
        deleted += [path for path in removed if kind.synced(path)]
        edited_count += len(edited)
        if edited:
            edited_kinds.add(kind.name)
        if edited or removed:
            changed_kinds.add(kind.name)
        for path in edited:
            report.add(kind.schema_check(path))
        if edited:
            for check in kind.repo_checks(kind.dir, args.base_sha):
                report.add(check)

    console.print(
        f"[cyan]PR validation:[/] {edited_count} changed/added, "
        f"{len(deleted)} deleted files"
    )
    # A detection can break without being touched, when the PR removes or
    # retypes a skill it names.
    if "detections" in edited_kinds or "skills" in changed_kinds:
        repo_skill_types = load_repo_skill_types(skills_dir)
        removed_skills: dict[str, str] = {}
        if "skills" in changed_kinds:
            removed_skills = {
                sid: path
                for sid, path in skill_ids_at(args.base_sha, skills_dir).items()
                if sid not in repo_skill_types
            }
        for check in detection_skill_ref_checks(
            detections_dir, repo_skill_types, removed_skills
        ):
            report.add(check)

    if not report.checks:
        console.print("[dim]Nothing to validate.[/]")
        _write_step_summary(Report(), deleted)
        return 0

    _print_report(report, deleted)
    _write_step_summary(report, deleted)
    return 0 if report.all_ok else 1


def _result_table(report: Report, deleted: list[str]) -> Table:
    t = Table(show_header=True, header_style="bold")
    t.add_column("OK", justify="center")
    t.add_column("File")
    t.add_column("Detail")
    for c in report.checks:
        if not c.schema_ok:
            t.add_row("[red]✗[/]", c.path, c.schema_error or "")
        elif c.warnings:
            t.add_row("[yellow]![/]", c.path, "; ".join(c.warnings))
        else:
            t.add_row("[green]✓[/]", c.path, "")
    for d in deleted:
        t.add_row("[yellow]-[/]", d, "will be deleted on merge")
    return t


def _print_report(report: Report, deleted: list[str]) -> None:
    schema_fails = [c for c in report.checks if not c.schema_ok]
    style = "green" if not schema_fails else "yellow"
    console.print(
        f"[{style}]files={len(report.checks)} "
        f"schema_fail={len(schema_fails)} "
        f"warnings={len(report.warned)} "
        f"deleted={len(deleted)}[/]"
    )
    console.print(_result_table(report, deleted))


def _render_text(*renderables: object) -> str:
    buf = io.StringIO()
    sink = Console(file=buf, width=_STEP_SUMMARY_WIDTH, force_terminal=False)
    for r in renderables:
        sink.print(r)
    return buf.getvalue()


def _write_step_summary(report: Report, deleted: list[str]) -> None:
    summary_file = os.environ.get("GITHUB_STEP_SUMMARY")
    if not summary_file:
        return

    schema_fails = [c for c in report.checks if not c.schema_ok]
    if not report.checks:
        header = "## ✅ No detection, skill or memory files changed"
    elif report.all_ok and report.warned:
        header = (
            f"## ⚠️ Schema validation passed with "
            f"{len(report.warned)} warning(s) "
            f"({len(report.checks)} file(s), {len(deleted)} deleted)"
        )
    elif report.all_ok:
        header = (
            f"## ✅ Schema validation passed "
            f"({len(report.checks)} file(s), {len(deleted)} deleted)"
        )
    else:
        header = (
            f"## ❌ Schema validation failed "
            f"({len(schema_fails)} issue(s), {len(deleted)} deleted)"
        )

    body = ""
    if report.checks or deleted:
        body = f"\n```\n{_render_text(_result_table(report, deleted))}```\n"

    footer = (
        "\n_KQL is validated at sync time. If your KQL is broken, the sync "
        "run after merge will fail with the API error._\n"
    )

    try:
        with open(summary_file, "a", encoding="utf-8") as fh:
            fh.write(f"{header}\n{body}{footer}")
    except OSError as e:
        console.print(f"[yellow]warning:[/] could not write step summary: {e}")


if __name__ == "__main__":
    sys.exit(main())
