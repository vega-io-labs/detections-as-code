"""PR-time validator: schema lint for changed detection YAMLs.

KQL validation is deliberately not done at PR time. The sync workflow's
createDetections/updateDetections calls validate KQL server-side on merge,
and any failure is reported in that run's step summary. Running a pre-flight
runFederatedQuery here would duplicate that check, cost tenant compute, and
introduce edge cases around multi-cell reference resolution that only the
deployment path resolves correctly.

Usage (in GitHub Actions):
  python -m scripts.pr_validate \
    --base-sha "$BASE_SHA" \
    --detections-dir ./detections

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

import yaml
from rich.console import Console
from rich.table import Table

from .translator import yaml_to_create_input

console = Console()

_STEP_SUMMARY_WIDTH = 160


@dataclass
class FileCheck:
    path: str
    schema_ok: bool
    schema_error: str | None = None
    detection_id: str | None = None
    detection_name: str | None = None


@dataclass
class Report:
    checks: list[FileCheck] = field(default_factory=list)

    @property
    def all_ok(self) -> bool:
        return all(c.schema_ok for c in self.checks)


def changed_yaml_paths(
    base_sha: str, detections_dir: Path
) -> tuple[list[Path], list[str]]:
    rel = detections_dir.relative_to(Path.cwd())
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
        if not (path.endswith(".yaml") or path.endswith(".yml")):
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
    check.detection_id = doc.get("id")
    check.detection_name = doc.get("name")
    try:
        yaml_to_create_input(doc)
        check.schema_ok = True
    except (ValueError, KeyError) as e:
        check.schema_error = str(e)
    return check


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Validate detection YAMLs in a PR."
    )
    parser.add_argument("--base-sha", required=True)
    parser.add_argument("--detections-dir", default="./detections")
    args = parser.parse_args()

    detections_dir = Path(args.detections_dir).resolve()
    edited, deleted = changed_yaml_paths(args.base_sha, detections_dir)

    console.print(
        f"[cyan]PR validation:[/] {len(edited)} changed/added, "
        f"{len(deleted)} deleted YAMLs"
    )
    if not edited:
        console.print("[dim]No YAMLs to validate.[/]")
        _write_step_summary(Report(), [])
        return 0

    report = Report()
    for path in edited:
        report.checks.append(schema_check(path))

    _print_report(report, deleted)
    _write_step_summary(report, deleted)
    return 0 if report.all_ok else 1


def _result_table(report: Report, deleted: list[str]) -> Table:
    t = Table(show_header=True, header_style="bold")
    t.add_column("OK", justify="center")
    t.add_column("File")
    t.add_column("Detail")
    for c in report.checks:
        ok = "[green]✓[/]" if c.schema_ok else "[red]✗[/]"
        detail = (c.schema_error or "") if not c.schema_ok else ""
        t.add_row(ok, c.path, detail)
    for d in deleted:
        t.add_row("[yellow]-[/]", d, "will be deleted on merge")
    return t


def _print_report(report: Report, deleted: list[str]) -> None:
    schema_fails = [c for c in report.checks if not c.schema_ok]
    style = "green" if not schema_fails else "yellow"
    console.print(
        f"[{style}]files={len(report.checks)} "
        f"schema_fail={len(schema_fails)} "
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
        header = "## ✅ No detection YAMLs changed"
    elif report.all_ok:
        header = (
            f"## ✅ Detection schema validation passed "
            f"({len(report.checks)} file(s), {len(deleted)} deleted)"
        )
    else:
        header = (
            f"## ❌ Detection schema validation failed "
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
