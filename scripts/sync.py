"""CLI: reconcile detections, skills and memories against a Vega tenant.

Usage:
  python -m scripts.sync \
    --detections-dir ./detections \
    [--detections-dir ./more-detections ...] \
    [--skills-dir ./skills ...] \
    [--memories-dir ./memories ...] \
    [--tenant-url https://app.vega.io] \
    [--dry-run] [--no-deletes]

Auth: VEGA_ACCESS_KEY env (or --access-key).
"""

from __future__ import annotations

import io
import os
import sys
from pathlib import Path
from typing import Any

import click
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from .client import DEFAULT_TENANT_URL, VegaAPIError, VegaClient
from .memory_reconciler import (
    MemoriesUnavailable,
    MemoryPlan,
    build_memory_plan,
    execute_memory_plan,
    fetch_memory_state,
    load_yaml_memories,
)
from .memory_translator import MemorySpec
from .plan import Plan, SyncReport
from .reconciler import (
    DetectionPlan,
    build_plan,
    execute_plan,
    load_yaml_detections,
)
from .skill_reconciler import (
    build_skill_plan,
    execute_skill_plan,
    hold_back_detections,
    load_skill_files,
    resolve_detection_skill_ids,
    skill_ids_by_external_id,
)
from .skill_translator import SkillSpec
from .translator import yaml_to_create_input

console = Console()

_STEP_SUMMARY_WIDTH = 160


class SkillSync:
    name = "skills"
    title = "Skill plan"

    def __init__(self, dirs: tuple[Path, ...]) -> None:
        self.dirs = dirs
        self.specs: list[SkillSpec] = []
        self.vega: list[dict[str, Any]] = []
        self.tenant_ids: dict[str, str] = {}
        self.plan: Plan | None = None

    def load(self) -> None:
        self.specs = load_skill_files(self.dirs)
        console.print(f"Loaded [bold]{len(self.specs)}[/] skill(s).")

    def fetch(self, client: VegaClient) -> None:
        self.vega = client.get_skills()
        self.tenant_ids = skill_ids_by_external_id(self.vega)
        console.print(
            f"Found [bold]{len(self.tenant_ids)}[/] managed skill(s) in tenant."
        )

    def build(self, dry_run: bool) -> None:
        self.plan = build_skill_plan(self.specs, self.vega)

    def execute(
        self, client: VegaClient, no_deletes: bool, report: SyncReport
    ) -> None:
        if self.plan is None:
            return
        results = execute_skill_plan(
            client, self.plan, skip_deletes=no_deletes
        ).results
        report.results.extend(results)
        if any(r.kind == "create" and r.success for r in results):
            try:
                self.tenant_ids = skill_ids_by_external_id(client.get_skills())
            except VegaAPIError as e:
                # Without the re-read the new skills have no tenant id, so the
                # detections naming them are held back; existing ones still
                # resolve.
                report.errors.append(
                    f"skills: could not re-read skills after creating them: {e}"
                )

    def notes(self) -> list[str]:
        return []


class DetectionSync:
    name = "detections"
    title = "Detection plan"

    def __init__(self, dirs: tuple[Path, ...], skills: SkillSync | None) -> None:
        self.dirs = dirs
        self.skills = skills
        self.yamls: list[dict[str, Any]] = []
        self.vega: list[dict[str, Any]] = []
        self.plan: DetectionPlan | None = None

    def load(self) -> None:
        console.print(
            f"[cyan]Loading YAMLs from[/] {', '.join(str(d) for d in self.dirs)}"
        )
        self.yamls = load_yaml_detections(self.dirs)
        # Skills are written before detections are planned, so a broken
        # detection has to stop the run here, before anything is written.
        for doc in self.yamls:
            yaml_to_create_input(doc)
        console.print(f"Loaded [bold]{len(self.yamls)}[/] YAML detection(s).")

    def fetch(self, client: VegaClient) -> None:
        self.vega = client.get_detections()
        console.print(f"Found [bold]{len(self.vega)}[/] detection(s) in tenant.")

    def build(self, dry_run: bool) -> None:
        yamls = self.yamls
        unresolved: dict[str, list[str]] = {}
        if self.skills is not None:
            known = dict(self.skills.tenant_ids)
            # A dry run writes no skills, so a skill this run would create has
            # no tenant id yet. Its own id stands in for it: attaching it is a
            # real change either way, and a skill that would not sync is held
            # back here the same as in a real run.
            if dry_run and self.skills.plan is not None:
                known |= {
                    e.external_id: e.external_id for e in self.skills.plan.creates
                }
            yamls, unresolved = resolve_detection_skill_ids(
                yamls, self.skills.specs, known
            )
        self.plan = build_plan(yamls, self.vega)
        hold_back_detections(self.plan, unresolved)

    def execute(
        self, client: VegaClient, no_deletes: bool, report: SyncReport
    ) -> None:
        if self.plan is None:
            return
        report.results.extend(
            execute_plan(client, self.plan, skip_deletes=no_deletes).results
        )

    def notes(self) -> list[str]:
        return []


class MemorySync:
    name = "memories"
    title = "Memory plan"

    def __init__(self, dirs: tuple[Path, ...]) -> None:
        self.dirs = dirs
        self.specs: list[MemorySpec] = []
        self.labels: list[dict[str, Any]] = []
        self.vega: list[dict[str, Any]] = []
        self.available = False
        self.plan: MemoryPlan | None = None

    def load(self) -> None:
        self.specs = load_yaml_memories(self.dirs)
        console.print(f"Loaded [bold]{len(self.specs)}[/] YAML memory(s).")

    def fetch(self, client: VegaClient) -> None:
        try:
            self.labels, self.vega = fetch_memory_state(client)
        except MemoriesUnavailable as e:
            # Only an error when the repo actually holds memories: an empty
            # memories/ folder on a tenant without the feature is fine.
            if self.specs:
                raise
            console.print(f"[dim]Skipping memory sync: {e}.[/]")
            return
        self.available = True
        console.print(f"Read [bold]{len(self.vega)}[/] memory(s) in tenant.")

    def build(self, dry_run: bool) -> None:
        if self.available:
            self.plan = build_memory_plan(self.specs, self.vega, self.labels)

    def execute(
        self, client: VegaClient, no_deletes: bool, report: SyncReport
    ) -> None:
        if self.plan is None:
            return
        report.results.extend(
            execute_memory_plan(client, self.plan, skip_deletes=no_deletes).results
        )

    def notes(self) -> list[str]:
        plan = self.plan
        if plan is not None and plan.managed_label_id is None and plan.creates:
            return [
                "The 'detections-as-code' label does not exist yet; "
                "the sync creates it before the first memory."
            ]
        return []


Kind = SkillSync | DetectionSync | MemorySync


@click.command(help="Reconcile detections, skills and memories against a Vega tenant.")
@click.option(
    "--detections-dir",
    "detections_dirs",
    type=click.Path(exists=True, file_okay=False, path_type=Path),
    multiple=True,
    default=("./detections",),
    show_default=True,
    help="Directory containing detection YAMLs. Pass multiple times to "
    "merge several directories.",
)
@click.option(
    "--skills-dir",
    "skills_dirs",
    type=click.Path(file_okay=False, path_type=Path),
    multiple=True,
    default=("./skills",),
    show_default=True,
    help="Directory containing skill folders with a SKILL.md each. Pass "
    "multiple times to merge several directories. When none of them exists, "
    "skills are not synced at all.",
)
@click.option(
    "--memories-dir",
    "memories_dirs",
    type=click.Path(file_okay=False, path_type=Path),
    multiple=True,
    default=("./memories",),
    show_default=True,
    help="Directory containing memory YAMLs. Pass multiple times to merge "
    "several directories. When none of them exists, memories are not synced "
    "at all.",
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
    "--dry-run",
    is_flag=True,
    help="Print the plan without applying it.",
)
@click.option(
    "--no-deletes",
    is_flag=True,
    help="Skip the delete step. Useful for first-run / staged adoption.",
)
def main(
    detections_dirs: tuple[Path, ...],
    skills_dirs: tuple[Path, ...],
    memories_dirs: tuple[Path, ...],
    tenant_url: str,
    access_key: str | None,
    access_key_id: str | None,
    scope_id: str | None,
    dry_run: bool,
    no_deletes: bool,
) -> None:
    if not access_key:
        console.print(
            "[red]ERROR:[/] missing access key. Set VEGA_ACCESS_KEY or pass --access-key.",
        )
        sys.exit(2)

    kinds = _kinds(detections_dirs, skills_dirs, memories_dirs)
    for kind in kinds:
        kind.load()

    console.print(f"[cyan]Authenticating to[/] {tenant_url}")
    client = VegaClient.login(
        access_key,
        tenant_url=tenant_url,
        access_key_id=access_key_id,
        scope_id=scope_id,
    )

    report = SyncReport()
    for kind in kinds:
        try:
            kind.fetch(client)
            kind.build(dry_run)
            if kind.plan is None:
                continue
            _print_plan(kind, kind.plan)
            if not dry_run:
                kind.execute(client, no_deletes, report)
        except (VegaAPIError, RuntimeError) as e:
            console.print(f"[red]ERROR:[/] {kind.name}: {e}")
            report.errors.append(f"{kind.name}: {e}")

    if dry_run:
        console.print(Panel.fit("DRY RUN - nothing applied", style="yellow"))
    else:
        _print_report(report)
    _write_step_summary(report, kinds, dry_run)
    sys.exit(0 if report.all_ok else 1)


def _kinds(
    detections_dirs: tuple[Path, ...],
    skills_dirs: tuple[Path, ...],
    memories_dirs: tuple[Path, ...],
) -> list[Kind]:
    resolved = tuple(d.resolve() for d in detections_dirs)
    # A missing directory turns that sync off rather than meaning "none",
    # which would delete everything the repo manages. Forks that predate
    # skills or memories keep working against tenants without them.
    skill_dirs = tuple(d.resolve() for d in skills_dirs if d.exists())
    memory_dirs = tuple(d.resolve() for d in memories_dirs if d.exists())
    skills = SkillSync(skill_dirs) if skill_dirs else None
    if skills is None:
        console.print("[dim]No skills directory; skipping skill sync.[/]")
    if not memory_dirs:
        console.print("[dim]No memories directory; skipping memory sync.[/]")

    # Skills go first so that a detection naming a new skill finds it.
    kinds: list[Kind] = []
    if skills is not None:
        kinds.append(skills)
    kinds.append(DetectionSync(resolved, skills))
    if memory_dirs:
        kinds.append(MemorySync(memory_dirs))
    return kinds


def _plan_table(title: str, plan: Plan) -> Table:
    t = Table(title=title, show_lines=False)
    t.add_column("Action", style="bold")
    t.add_column("Count", justify="right")
    t.add_row("[green]create[/]", str(len(plan.creates)))
    t.add_row("[yellow]update[/]", str(len(plan.updates)))
    t.add_row("[red]delete[/]", str(len(plan.deletes)))
    t.add_row("[red]blocked[/]", str(len(plan.blocked)))
    t.add_row("[dim]no-op skipped[/]", str(plan.no_op_updates))
    return t


def _print_plan(kind: Kind, plan: Plan) -> None:
    console.print(_plan_table(kind.title, plan))
    for b in plan.blocked:
        console.print(f"[red]blocked:[/] {b.name}: {b.reason}")
    for note in kind.notes():
        console.print(f"[dim]{note}[/]")


def _report_table(report: SyncReport) -> Table:
    t = Table(show_header=True, header_style="bold")
    t.add_column("OK", justify="center")
    t.add_column("Object")
    t.add_column("Action")
    t.add_column("Id")
    t.add_column("Name")
    t.add_column("Error")
    for r in report.results:
        ok = "[green]✓[/]" if r.success else "[red]✗[/]"
        err = (r.error or "")[:200] if not r.success else ""
        t.add_row(ok, r.target, r.kind, r.external_id, r.name, err)
    return t


def _print_report(report: SyncReport) -> None:
    style = "green" if report.all_ok else "yellow"
    console.print(
        Panel.fit(
            f"[bold]Sync report[/]  "
            f"[green]succeeded={len(report.succeeded)}[/]  "
            f"[red]failed={len(report.failed)}[/]  "
            f"[red]errors={len(report.errors)}[/]",
            style=style,
        )
    )
    for error in report.errors:
        console.print(f"[red]run error:[/] {error}")
    if not report.results:
        console.print("[dim](no actions taken)[/]")
        return
    console.print(_report_table(report))


def _render_text(*renderables: object) -> str:
    buf = io.StringIO()
    sink = Console(file=buf, width=_STEP_SUMMARY_WIDTH, force_terminal=False)
    for r in renderables:
        sink.print(r)
    return buf.getvalue()


def _write_step_summary(
    report: SyncReport, kinds: list[Kind], dry_run: bool
) -> None:
    summary_file = os.environ.get("GITHUB_STEP_SUMMARY")
    if not summary_file:
        return

    icon = "✅" if report.all_ok else "⚠️"
    title = "Vega sync dry run" if dry_run else "Vega sync"
    lines = [
        f"## {icon} {title}: {len(report.succeeded)} ok, "
        f"{len(report.failed)} failed, {len(report.errors)} run error(s)"
    ]
    for kind in kinds:
        summary = kind.plan.summary() if kind.plan is not None else "not planned"
        lines.append(f"{kind.title}: {summary}")
    lines += [f"Run error: {error}" for error in report.errors]
    body = ""
    if report.results:
        body = f"\n```\n{_render_text(_report_table(report))}```\n"

    try:
        with open(summary_file, "a", encoding="utf-8") as fh:
            fh.write("\n\n".join(lines) + f"\n{body}")
    except OSError as e:
        console.print(f"[yellow]warning:[/] could not write step summary: {e}")


if __name__ == "__main__":
    main()
