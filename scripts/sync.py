"""CLI: reconcile detection YAMLs against a Vega tenant.

Usage:
  python -m scripts.sync \
    --detections-dir ./detections \
    [--detections-dir ./more-detections ...] \
    [--tenant-url https://app.vega.io] \
    [--dry-run] [--no-deletes]

Auth: VEGA_ACCESS_KEY env (or --access-key).
"""

from __future__ import annotations

import io
import os
import sys
from pathlib import Path

import click
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from .client import DEFAULT_TENANT_URL, VegaClient
from .reconciler import (
    Plan,
    SyncReport,
    build_plan,
    execute_plan,
    load_yaml_detections,
)

console = Console()

_STEP_SUMMARY_WIDTH = 160


@click.command(help="Reconcile detection YAMLs against a Vega tenant.")
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

    resolved_dirs = tuple(d.resolve() for d in detections_dirs)
    console.print(
        f"[cyan]Loading YAMLs from[/] {', '.join(str(d) for d in resolved_dirs)}"
    )
    yamls = load_yaml_detections(resolved_dirs)
    console.print(f"Loaded [bold]{len(yamls)}[/] YAML detection(s).")

    console.print(f"[cyan]Authenticating to[/] {tenant_url}")
    client = VegaClient.login(
        access_key,
        tenant_url=tenant_url,
        access_key_id=access_key_id,
        scope_id=scope_id,
    )

    console.print("[cyan]Fetching current Vega state...[/]")
    vega = client.get_detections()
    console.print(f"Found [bold]{len(vega)}[/] detection(s) in tenant.")

    plan = build_plan(yamls, vega)
    _print_plan(plan)

    if dry_run:
        console.print(Panel.fit("DRY RUN - nothing applied", style="yellow"))
        return

    report = execute_plan(
        client, plan, dry_run=False, skip_deletes=no_deletes
    )
    _print_report(report)
    _write_step_summary(report, plan)

    if not report.all_ok:
        sys.exit(1)


def _plan_table(plan: Plan) -> Table:
    t = Table(title="Plan", show_lines=False)
    t.add_column("Action", style="bold")
    t.add_column("Count", justify="right")
    t.add_row("[green]create[/]", str(len(plan.creates)))
    t.add_row("[yellow]update[/]", str(len(plan.updates)))
    t.add_row("[red]delete[/]", str(len(plan.deletes)))
    t.add_row("[dim]no-op skipped[/]", str(plan.no_op_updates))
    return t


def _report_table(report: SyncReport) -> Table:
    t = Table(show_header=True, header_style="bold")
    t.add_column("OK", justify="center")
    t.add_column("Action")
    t.add_column("externalId")
    t.add_column("Name")
    t.add_column("Error")
    for r in report.results:
        ok = "[green]✓[/]" if r.success else "[red]✗[/]"
        err = (r.error or "")[:200] if not r.success else ""
        t.add_row(ok, r.kind, r.external_id, r.name, err)
    return t


def _print_plan(plan: Plan) -> None:
    console.print(_plan_table(plan))


def _print_report(report: SyncReport) -> None:
    style = "green" if report.all_ok else "yellow"
    console.print(
        Panel.fit(
            f"[bold]Sync report[/]  "
            f"[green]succeeded={len(report.succeeded)}[/]  "
            f"[red]failed={len(report.failed)}[/]",
            style=style,
        )
    )
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


def _write_step_summary(report: SyncReport, plan: Plan) -> None:
    summary_file = os.environ.get("GITHUB_STEP_SUMMARY")
    if not summary_file:
        return

    icon = "✅" if report.all_ok else "⚠️"
    header = (
        f"## {icon} Detection sync — {len(report.succeeded)} ok, "
        f"{len(report.failed)} failed "
        f"(creates={len(plan.creates)} updates={len(plan.updates)} "
        f"deletes={len(plan.deletes)} no_op={plan.no_op_updates})"
    )
    body = ""
    if report.results:
        body = f"\n```\n{_render_text(_report_table(report))}```\n"

    try:
        with open(summary_file, "a", encoding="utf-8") as fh:
            fh.write(f"{header}\n{body}")
    except OSError as e:
        console.print(f"[yellow]warning:[/] could not write step summary: {e}")


if __name__ == "__main__":
    main()
