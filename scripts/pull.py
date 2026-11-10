"""CLI: pull tenant changes into the files of this repository.

Usage:
  python -m scripts.pull \
    --detections-dir ./detections \
    [--skills-dir ./skills ...] \
    [--memories-dir ./memories ...] \
    [--tenant-url https://app.vega.io] \
    [--pr-body-file body.md] [--dry-run]

The mirror of scripts.sync: it reads the tenant and rewrites the files under
the given folders so that the next sync finds nothing to do. Objects edited or
created in the Vega UI become edited or new files, objects deleted there
become deleted files. Nothing is written to the tenant.

Auth: VEGA_ACCESS_KEY env (or --access-key).
"""

from __future__ import annotations

import io
import os
import shutil
import sys
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable, Literal

import click
import yaml
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from .client import DEFAULT_TENANT_URL, VegaAPIError, VegaClient
from .consts import MANAGED_MEMORY_LABEL, SKILL_FILE_NAME
from .export import (
    DETECTION_KEY_ORDER,
    MEMORY_KEY_ORDER,
    ExportError,
    detection_file,
    detection_matches,
    memory_file,
    memory_matches,
    render,
    skill_file,
    skill_matches,
    slug,
    verify_detection,
    verify_memory,
    verify_skill,
)
from .labels import label_ids_by_name
from .memory_reconciler import (
    MemoriesUnavailable,
    MemoryState,
    fetch_memory_state,
    index_by_title,
)
from .memory_translator import MemorySpec, parse_memory
from .plan import Target
from .reconciler import is_library
from .skill_reconciler import (
    load_skill_files,
    managed_skills,
    skill_ids_by_external_id,
)
from .skill_translator import SkillSpec
from .utils import UniqueKey, load_unique, yaml_files

console = Console()

_STEP_SUMMARY_WIDTH = 160

Action = Literal["add", "update", "remove"]


@dataclass(frozen=True)
class Change:
    target: Target
    action: Action
    path: Path
    external_id: str
    name: str
    detail: str = ""
    text: str | None = None


@dataclass
class PullReport:
    changes: list[Change] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)

    @property
    def ok(self) -> bool:
        return not self.errors


def _new_path(taken: set[Path], candidates: Iterable[Path]) -> Path:
    for path in candidates:
        if path not in taken and not path.exists():
            taken.add(path)
            return path
    raise ExportError("could not find a free file name")


def _changed_keys(
    before: dict[str, Any], after: dict[str, Any], order: tuple[str, ...]
) -> str:
    keys = [
        k
        for k in order
        if (k in before or k in after) and before.get(k) != after.get(k)
    ]
    keys += sorted(
        k
        for k in set(before) | set(after)
        if k not in order and before.get(k) != after.get(k)
    )
    return ", ".join(keys)


# --------------------------------------------------------------------------
# Detections
# --------------------------------------------------------------------------


@dataclass(frozen=True)
class _DetectionFile:
    path: Path
    text: str
    doc: dict[str, Any]


def _load_detection_files(dirs: Iterable[Path]) -> list[_DetectionFile]:
    def parse(path: Path) -> _DetectionFile | None:
        text = path.read_text(encoding="utf-8")
        doc = yaml.safe_load(text)
        if doc is None:
            return None
        if not isinstance(doc, dict) or "id" not in doc:
            raise ValueError(f"{path}: YAML missing required 'id'")
        return _DetectionFile(path, text, doc)

    return load_unique(
        (f for d in dirs for f in yaml_files(d)),
        parse,
        [UniqueKey("id", lambda f: str(f.doc["id"]).strip())],
    )


def pull_detections(
    dirs: tuple[Path, ...],
    vega_detections: list[dict[str, Any]],
    skill_tenant_ids: dict[str, str] | None,
) -> tuple[list[Change], list[str]]:
    """Changes that make the detection files match the tenant, and notes on
    the detections that could not be written as files.

    `skill_tenant_ids` maps repository skill ids to tenant ids, or is None when
    skills are not managed here, in which case skill ids stay tenant ids.
    """
    files = {str(f.doc["id"]).strip(): f for f in _load_detection_files(dirs)}
    tenant = {d["externalId"]: d for d in vega_detections if d.get("externalId")}
    ext_to_tenant = skill_tenant_ids or {}
    tenant_to_ext = {v: k for k, v in ext_to_tenant.items()}
    taken = {f.path for f in files.values()}
    changes: list[Change] = []
    notes: list[str] = []

    for ext_id, vega in tenant.items():
        current = files.get(ext_id)
        # Library detections are Vega's: the sync never deletes them and this
        # never writes them, unless a file here already claims one.
        if current is None and is_library(vega):
            continue
        if current is not None and detection_matches(current.doc, vega, ext_to_tenant):
            continue
        doc = detection_file(vega, current.doc if current else None, tenant_to_ext)
        text = render(doc, current.text if current else None, DETECTION_KEY_ORDER)
        try:
            verify_detection(text, vega, ext_to_tenant)
        except ExportError as e:
            notes.append(f"Detection {vega.get('name') or ext_id!r} not pulled: {e}")
            continue
        name = vega.get("name") or ext_id
        if current is None:
            stem = slug(name) or ext_id
            path = _new_path(
                taken,
                (
                    dirs[0] / f"{stem}.yaml",
                    dirs[0] / f"{stem}-{ext_id[:8]}.yaml",
                    dirs[0] / f"{ext_id}.yaml",
                ),
            )
            changes.append(Change("detection", "add", path, ext_id, name, "", text))
        else:
            changes.append(
                Change(
                    "detection",
                    "update",
                    current.path,
                    ext_id,
                    name,
                    _changed_keys(current.doc, doc, DETECTION_KEY_ORDER),
                    text,
                )
            )

    for ext_id, current in files.items():
        if ext_id not in tenant:
            changes.append(
                Change(
                    "detection",
                    "remove",
                    current.path,
                    ext_id,
                    str(current.doc.get("name") or ext_id),
                )
            )
    return changes, notes


# --------------------------------------------------------------------------
# Skills
# --------------------------------------------------------------------------


def _skill_changed(spec: SkillSpec, vega: dict[str, Any]) -> str:
    changed = []
    if spec.name != (vega.get("name") or "").strip():
        changed.append("name")
    if spec.description != (vega.get("description") or "").strip():
        changed.append("description")
    if spec.type.value != vega.get("type"):
        changed.append("type")
    if spec.instructions != (vega.get("instructions") or "").strip():
        changed.append("instructions")
    return ", ".join(changed)


def pull_skills(
    dirs: tuple[Path, ...], vega_skills: list[dict[str, Any]]
) -> tuple[list[Change], list[str]]:
    """Changes that make the SKILL.md files match the tenant's managed skills,
    and notes on the skills that could not be written as files."""
    specs = {spec.external_id: spec for spec in load_skill_files(dirs)}
    managed = {s["externalId"]: s for s in managed_skills(vega_skills)}
    taken = {Path(spec.path) for spec in specs.values()}
    changes: list[Change] = []
    notes: list[str] = []

    for ext_id, vega in managed.items():
        spec = specs.get(ext_id)
        if spec is not None and skill_matches(spec, vega):
            continue
        existing_text = (
            Path(spec.path).read_text(encoding="utf-8") if spec else None
        )
        name = vega.get("name") or ext_id
        if spec is None:
            stem = slug(name) or ext_id
            path = _new_path(
                taken,
                (
                    dirs[0] / stem / SKILL_FILE_NAME,
                    dirs[0] / f"{stem}-{ext_id[:8]}" / SKILL_FILE_NAME,
                    dirs[0] / ext_id / SKILL_FILE_NAME,
                ),
            )
        else:
            path = Path(spec.path)
        text = skill_file(vega, existing_text)
        try:
            verify_skill(text, vega, str(path))
        except (ExportError, ValueError) as e:
            notes.append(f"Skill {name!r} not pulled: {e}")
            continue
        if spec is None:
            changes.append(Change("skill", "add", path, ext_id, name, "", text))
        else:
            changes.append(
                Change("skill", "update", path, ext_id, name, _skill_changed(spec, vega), text)
            )

    for ext_id, spec in specs.items():
        if ext_id not in managed:
            changes.append(Change("skill", "remove", Path(spec.path), ext_id, spec.name))
    return changes, notes


# --------------------------------------------------------------------------
# Memories
# --------------------------------------------------------------------------


@dataclass(frozen=True)
class _MemoryFile:
    path: Path
    text: str
    doc: dict[str, Any]
    spec: MemorySpec


def _load_memory_files(dirs: Iterable[Path]) -> list[_MemoryFile]:
    def parse(path: Path) -> _MemoryFile | None:
        text = path.read_text(encoding="utf-8")
        doc = yaml.safe_load(text)
        if doc is None:
            return None
        return _MemoryFile(path, text, doc, parse_memory(doc, str(path)))

    return load_unique(
        (f for d in dirs for f in yaml_files(d)),
        parse,
        [UniqueKey("title", lambda f: f.spec.title)],
    )


def pull_memories(
    dirs: tuple[Path, ...], state: MemoryState
) -> tuple[list[Change], list[str]]:
    """Changes that make the memory files match the tenant's labelled memories.

    Also returns notes for the files it deliberately leaves alone.
    """
    label_ids = label_ids_by_name(state.labels)
    managed_id = label_ids.get(MANAGED_MEMORY_LABEL)
    if managed_id is None:
        return [], [
            f"Memories were not pulled: the '{MANAGED_MEMORY_LABEL}' label does "
            f"not exist in the tenant yet, so no memory there belongs to this "
            f"repository. The first sync creates it."
        ]
    files = {f.spec.title: f for f in _load_memory_files(dirs)}
    tenant = index_by_title(state.memories, managed_id)
    taken = {f.path for f in files.values()}
    changes: list[Change] = []
    notes: list[str] = []

    for title, vega in tenant.managed.items():
        current = files.get(title)
        if current is not None and memory_matches(current.spec, vega, label_ids, managed_id):
            continue
        doc = memory_file(vega, current.doc if current else None)
        text = render(doc, current.text if current else None, MEMORY_KEY_ORDER)
        memory_id = vega.get("vegaMemoryId") or ""
        if current is None:
            stem = slug(title) or slug(memory_id) or "memory"
            path = _new_path(
                taken,
                (
                    dirs[0] / f"{stem}.yaml",
                    dirs[0] / f"{stem}-{slug(memory_id)}.yaml",
                ),
            )
        else:
            path = current.path
        try:
            verify_memory(text, vega, str(path), label_ids, managed_id)
        except (ExportError, ValueError) as e:
            notes.append(f"Memory {title!r} not pulled: {e}")
            continue
        if current is None:
            changes.append(Change("memory", "add", path, memory_id, title, "", text))
        else:
            changes.append(
                Change(
                    "memory",
                    "update",
                    path,
                    memory_id,
                    title,
                    _changed_keys(current.doc, doc, MEMORY_KEY_ORDER),
                    text,
                )
            )

    for title, current in files.items():
        if title in tenant.managed:
            continue
        # The sync blocks on this file rather than creating a duplicate, and
        # deleting it here would silently settle that in the UI's favour.
        if title in tenant.unmanaged:
            notes.append(
                f"{current.path}: left in place. A memory titled {title!r} "
                f"exists in the tenant without the '{MANAGED_MEMORY_LABEL}' "
                f"label; add the label in Vega to hand it to the sync, or "
                f"delete one of the two."
            )
            continue
        changes.append(Change("memory", "remove", current.path, "", title))
    return changes, notes


# --------------------------------------------------------------------------
# Applying and reporting
# --------------------------------------------------------------------------


def _prune_empty_dirs(directory: Path, roots: Iterable[Path]) -> None:
    stop = {r.resolve() for r in roots}
    while directory.resolve() not in stop and directory.is_dir():
        if any(directory.iterdir()):
            return
        directory.rmdir()
        directory = directory.parent


def _remove_skill(path: Path, roots: Iterable[Path]) -> None:
    # A skill folder may hold references next to its SKILL.md; the sync
    # ignores them, but leaving them behind would orphan them in the repo.
    folder = path.parent
    if folder.resolve() in {r.resolve() for r in roots}:
        path.unlink(missing_ok=True)
        return
    shutil.rmtree(folder, ignore_errors=True)
    _prune_empty_dirs(folder.parent, roots)


def apply_changes(changes: list[Change], skill_roots: Iterable[Path]) -> None:
    for change in changes:
        if change.action == "remove":
            if change.target == "skill":
                _remove_skill(change.path, skill_roots)
            else:
                change.path.unlink(missing_ok=True)
        else:
            change.path.parent.mkdir(parents=True, exist_ok=True)
            change.path.write_text(change.text or "", encoding="utf-8")


def _detail(change: Change) -> str:
    if change.action == "update":
        return change.detail
    return str(change.path)


def _cell(text: str) -> str:
    return text.replace("|", "\\|").replace("\n", " ")


def pr_body(report: PullReport, tenant_url: str, now: datetime | None = None) -> str:
    now = now or datetime.now(timezone.utc)
    lines = [
        f"Changes made in Vega ({tenant_url}) that this repository does not "
        f"have yet, as of {now:%Y-%m-%d %H:%M} UTC.",
        "",
    ]
    if report.changes:
        lines += [
            "| Object | Change | Id | Name | Details |",
            "|---|---|---|---|---|",
        ]
        for change in report.changes:
            lines.append(
                f"| {change.target} | {change.action} | `{_cell(change.external_id)}` "
                f"| {_cell(change.name)} | {_cell(_detail(change))} |"
            )
        lines.append("")
    if report.notes:
        lines += ["**Not pulled**", ""]
        lines += [f"- {note}" for note in report.notes]
        lines.append("")
    lines += [
        "Merging makes the repository match the tenant, so the sync that "
        "follows finds nothing to do. Each change was made by someone in the "
        "Vega UI or through the API; the detection's version history in Vega "
        "names them.",
        "",
        "To keep what the repository has instead, close this pull request "
        "and run **Sync ALL detections, skills and memories** with `dry_run` "
        "and `no_deletes` off. This branch is rebuilt from `main` on every "
        "pull, so it never needs a manual rebase.",
        "",
        "A removed file means the object is no longer in the tenant. If the "
        "file was added to the repository recently, check that the sync run "
        "after its merge succeeded before merging the removal: a failed "
        "create looks the same as a deletion from here.",
    ]
    return "\n".join(lines) + "\n"


def _changes_table(report: PullReport) -> Table:
    t = Table(show_header=True, header_style="bold")
    t.add_column("Object")
    t.add_column("Change")
    t.add_column("Id")
    t.add_column("Name")
    t.add_column("Details")
    colours = {"add": "green", "update": "yellow", "remove": "red"}
    for change in report.changes:
        t.add_row(
            change.target,
            f"[{colours[change.action]}]{change.action}[/]",
            change.external_id,
            change.name,
            _detail(change),
        )
    return t


def _render_text(*renderables: object) -> str:
    buf = io.StringIO()
    sink = Console(file=buf, width=_STEP_SUMMARY_WIDTH, force_terminal=False)
    for r in renderables:
        sink.print(r)
    return buf.getvalue()


def _counts(report: PullReport) -> str:
    return " ".join(
        f"{action}={sum(1 for c in report.changes if c.action == action)}"
        for action in ("add", "update", "remove")
    )


def _write_step_summary(report: PullReport, dry_run: bool) -> None:
    summary_file = os.environ.get("GITHUB_STEP_SUMMARY")
    if not summary_file:
        return
    icon = "✅" if report.ok else "⚠️"
    title = "Vega pull dry run" if dry_run else "Vega pull"
    lines = [
        f"## {icon} {title}: {len(report.changes)} file change(s), "
        f"{len(report.errors)} error(s)",
        _counts(report),
        *[f"Run error: {error}" for error in report.errors],
        *[f"Note: {note}" for note in report.notes],
    ]
    body = ""
    if report.changes:
        body = f"\n```\n{_render_text(_changes_table(report))}```\n"
    try:
        with open(summary_file, "a", encoding="utf-8") as fh:
            fh.write("\n\n".join(lines) + f"\n{body}")
    except OSError as e:
        console.print(f"[yellow]warning:[/] could not write step summary: {e}")


def _existing_dirs(dirs: tuple[Path, ...]) -> tuple[Path, ...]:
    return tuple(d.resolve() for d in dirs if d.exists())


@click.command(help="Pull tenant changes into the detection, skill and memory files.")
@click.option(
    "--detections-dir",
    "detections_dirs",
    type=click.Path(exists=True, file_okay=False, path_type=Path),
    multiple=True,
    default=("./detections",),
    show_default=True,
    help="Directory containing detection YAMLs. New detections are written "
    "to the first one.",
)
@click.option(
    "--skills-dir",
    "skills_dirs",
    type=click.Path(file_okay=False, path_type=Path),
    multiple=True,
    default=("./skills",),
    show_default=True,
    help="Directory containing skill folders. When none of them exists, "
    "skills are not pulled and detections keep tenant skill ids.",
)
@click.option(
    "--memories-dir",
    "memories_dirs",
    type=click.Path(file_okay=False, path_type=Path),
    multiple=True,
    default=("./memories",),
    show_default=True,
    help="Directory containing memory YAMLs. When none of them exists, "
    "memories are not pulled.",
)
@click.option(
    "--tenant-url",
    default=lambda: os.environ.get("VEGA_TENANT_URL") or DEFAULT_TENANT_URL,
    show_default=DEFAULT_TENANT_URL,
    help="Vega tenant base URL.",
)
@click.option(
    "--access-key",
    envvar="VEGA_ACCESS_KEY",
    help="Vega access key (default: $VEGA_ACCESS_KEY).",
)
@click.option(
    "--access-key-id",
    envvar="VEGA_ACCESS_KEY_ID",
    help="Vega access key ID (default: $VEGA_ACCESS_KEY_ID). Required for "
    "access keys created on or after 2026-06-18; older keys work without it.",
)
@click.option(
    "--scope-id",
    envvar="VEGA_SCOPE_ID",
    help="Vega scope UUID (default: $VEGA_SCOPE_ID). Only needed on "
    "ABAC-enabled tenants when the access key is bound to multiple scopes.",
)
@click.option(
    "--pr-body-file",
    type=click.Path(dir_okay=False, path_type=Path),
    help="Write a Markdown description of the changes here, for the pull "
    "request that carries them.",
)
@click.option(
    "--dry-run",
    is_flag=True,
    help="List the file changes without writing them.",
)
def main(
    detections_dirs: tuple[Path, ...],
    skills_dirs: tuple[Path, ...],
    memories_dirs: tuple[Path, ...],
    tenant_url: str,
    access_key: str | None,
    access_key_id: str | None,
    scope_id: str | None,
    pr_body_file: Path | None,
    dry_run: bool,
) -> None:
    if not access_key:
        console.print(
            "[red]ERROR:[/] missing access key. Set VEGA_ACCESS_KEY or pass --access-key.",
        )
        sys.exit(2)

    detection_dirs = tuple(d.resolve() for d in detections_dirs)
    skill_dirs = _existing_dirs(skills_dirs)
    memory_dirs = _existing_dirs(memories_dirs)
    if not skill_dirs:
        console.print("[dim]No skills directory; skills are not pulled.[/]")
    if not memory_dirs:
        console.print("[dim]No memories directory; memories are not pulled.[/]")

    console.print(f"[cyan]Authenticating to[/] {tenant_url}")
    client = VegaClient.login(
        access_key,
        tenant_url=tenant_url,
        access_key_id=access_key_id,
        scope_id=scope_id,
    )

    report = PullReport()
    skill_tenant_ids: dict[str, str] | None = None
    skills_ok = True
    if skill_dirs:
        try:
            vega_skills = client.get_skills()
            skill_tenant_ids = skill_ids_by_external_id(vega_skills)
            changes, notes = pull_skills(skill_dirs, vega_skills)
            report.changes += changes
            report.notes += notes
        except (VegaAPIError, ValueError, RuntimeError) as e:
            skills_ok = False
            report.errors.append(f"skills: {e}")

    # Detection files name repository skills by the id in their SKILL.md, so
    # without the skills the ids cannot be translated and would be rewritten
    # to tenant ids.
    if not skills_ok:
        report.errors.append(
            "detections: not pulled because the skills could not be read"
        )
    else:
        try:
            changes, notes = pull_detections(
                detection_dirs, client.get_detections(), skill_tenant_ids
            )
            report.changes += changes
            report.notes += notes
        except (VegaAPIError, ValueError, RuntimeError) as e:
            report.errors.append(f"detections: {e}")

    if memory_dirs:
        try:
            changes, notes = pull_memories(memory_dirs, fetch_memory_state(client))
            report.changes += changes
            report.notes += notes
        except MemoriesUnavailable as e:
            report.notes.append(f"Memories were not pulled: {e}.")
        except (VegaAPIError, ValueError, RuntimeError) as e:
            report.errors.append(f"memories: {e}")

    for error in report.errors:
        console.print(f"[red]ERROR:[/] {error}")
    for note in report.notes:
        console.print(f"[yellow]note:[/] {note}")
        if os.environ.get("GITHUB_ACTIONS"):
            print(f"::warning::{note}")
    if report.changes:
        console.print(_changes_table(report))
    else:
        console.print("[dim]The repository already matches the tenant.[/]")

    if dry_run:
        console.print(Panel.fit("DRY RUN - nothing written", style="yellow"))
    elif not report.ok:
        console.print(
            Panel.fit("Nothing written: a tenant read failed", style="red")
        )
    else:
        apply_changes(report.changes, skill_dirs)
        console.print(
            Panel.fit(f"Wrote {len(report.changes)} file change(s)", style="green")
        )
        if pr_body_file is not None:
            pr_body_file.write_text(pr_body(report, tenant_url), encoding="utf-8")

    _write_step_summary(report, dry_run)
    sys.exit(0 if report.ok else 1)


if __name__ == "__main__":
    main()
