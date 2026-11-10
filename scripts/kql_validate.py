"""PR-time KQL check: run every cell of the changed detections on the tenant.

The sync's createDetections/updateDetections only compile the trigger cell,
with a short timeout, and let through a data source that does not exist. This
check runs each cell through runFederatedQuery instead, one at a time, over a
short timeframe, and reports a failure on the file and line that caused it.

A cell can reference other cells of its detection (`@CellName`). The API only
resolves references to cells already saved in the tenant, which a new or
edited detection is not, so the cells a cell references are inlined before it
as `let` statements and the cell itself is the final statement. Cells run in
dependency order: every inlined cell has already passed on its own, so an
error always belongs to the cell under test. That matters because the engine
reports an error inside a `let` body at the wrong line.

Usage (in GitHub Actions):
  python -m scripts.kql_validate \
    --base-sha "$BASE_SHA" \
    --detections-dir ./detections

Needs VEGA_ACCESS_KEY (and VEGA_ACCESS_KEY_ID for newer keys) with the
QueryRead permission. Only the query is read; nothing is written to the tenant.
"""

from __future__ import annotations

import json
import os
import re
import sys
import time
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any, Callable, Iterable

import click
import yaml
from rich.console import Console
from rich.table import Table

from .client import ACCESS_DENIED, DEFAULT_TENANT_URL, VegaAPIError, VegaClient
from .pr_validate import changed_paths
from .translator import yaml_to_create_input
from .utils import yaml_files

# A runner log is not a terminal; at the default 80 columns the table wraps
# every path.
console = Console(width=200) if os.environ.get("GITHUB_ACTIONS") else Console()

DEFAULT_TIMEFRAME = "PT15M"
DEFAULT_TIMEOUT_S = 120
POLL_DELAYS_S = (0.5, 1, 1, 2, 3, 5)
# The engine cancels the query at the timeout itself; the grace lets that
# answer arrive before this side gives up and cancels.
CANCEL_GRACE_S = 15

INVALID_QUERY = "INVALID_QUERY"
QUERY_TIMEOUT = "QUERY_TIMEOUT"
RATE_LIMITED = "REQUEST_RATE_LIMITED"
# Every submit and status poll counts toward the tenant's per-minute limit;
# a pull request with a few dozen detections reaches it.
MAX_RATE_LIMIT_WAITS = 20
DEFAULT_RETRY_AFTER_S = 10
MAX_RETRY_AFTER_S = 60
QUERY_TARGET_NOT_FOUND = "QUERY_TARGET_NOT_FOUND"
UNKNOWN_CELL_REFERENCE = "UNKNOWN_CELL_REFERENCE_IN_QUERY"
# Codes a detection author fixes in the file. Anything else is the platform
# or the network, and is reported without failing the pull request.
_AUTHOR_ERROR_CODES = frozenset(
    {INVALID_QUERY, QUERY_TARGET_NOT_FOUND, UNKNOWN_CELL_REFERENCE}
)

# `@Name` or `@cells:<ref>/Name`. Not preceded by a word character, so the
# `@` of an email address in a string is left alone, and not followed by `:`,
# so `@lookup_tables:...` and `@data_type:...` are not taken for a cell.
_REFERENCE_RE = re.compile(
    r"(?<![\w@])@(?:cells:[A-Za-z0-9_-]+/)?([A-Za-z0-9_-]+)(?![\w:/-])"
)
_SELECTOR_RE = re.compile(r"(?<![\w@])@[A-Za-z0-9_:/-]+")
_LOCATION_RE = re.compile(r"\[\s*query:(\d+):(\d+)\s*\]")
_HELP_RE = re.compile(r"Help:\s*(.+)$", re.MULTILINE)


class Verdict(str, Enum):
    PASS = "pass"
    FAIL = "fail"
    WARN = "warn"
    SKIPPED = "skipped"


@dataclass(frozen=True)
class Cell:
    name: str
    body: str
    # 1-based line of the body's first line in the YAML file, when known.
    first_line: int | None
    trigger: bool


@dataclass(frozen=True)
class Detection:
    path: Path
    external_id: str
    name: str
    cells: tuple[Cell, ...]


@dataclass(frozen=True)
class Problem:
    message: str
    help: str | None = None
    line: int | None = None
    column: int | None = None


@dataclass
class CellResult:
    detection: Detection
    cell: Cell
    verdict: Verdict
    problems: list[Problem] = field(default_factory=list)
    code: str | None = None

    @property
    def summary(self) -> str:
        return "; ".join(p.message for p in self.problems)


# --------------------------------------------------------------------------
# Reading detections
# --------------------------------------------------------------------------


def _first_line(node: yaml.Node, value: str, file_lines: list[str]) -> int | None:
    if not isinstance(node, yaml.ScalarNode):
        return None
    if node.style in ("|", ">"):
        # The mark is on the indicator; the text starts on the next line.
        line = node.start_mark.line + 2
    else:
        line = node.start_mark.line + 1
    leading = value[: len(value) - len(value.lstrip())].count("\n")
    line += leading
    return line if line <= len(file_lines) else None


def _mapping_get(node: yaml.Node, key: str) -> yaml.Node | None:
    if not isinstance(node, yaml.MappingNode):
        return None
    for k, v in node.value:
        if isinstance(k, yaml.ScalarNode) and k.value == key:
            return v
    return None


def _query_lines(text: str) -> dict[tuple[str | None, int], int | None]:
    """First file line of each query, keyed by (cells key, cell index).

    A single-cell detection's `query` is keyed (None, 0).
    """
    file_lines = text.split("\n")
    root = yaml.compose(text)
    out: dict[tuple[str | None, int], int | None] = {}
    query = _mapping_get(root, "query")
    if isinstance(query, yaml.ScalarNode):
        out[(None, 0)] = _first_line(query, query.value, file_lines)
    for key in ("cells", "detectionCells"):
        cells = _mapping_get(root, key)
        if not isinstance(cells, yaml.SequenceNode):
            continue
        for i, cell in enumerate(cells.value):
            cell_query = _mapping_get(cell, "query")
            if isinstance(cell_query, yaml.ScalarNode):
                out[(key, i)] = _first_line(cell_query, cell_query.value, file_lines)
    return out


def load_detection(path: Path) -> Detection:
    """Raises ValueError when the file does not pass the schema check."""
    text = path.read_text(encoding="utf-8")
    doc = yaml.safe_load(text)
    if not isinstance(doc, dict):
        raise ValueError(f"{path}: not a YAML mapping")
    payload = yaml_to_create_input(doc)
    lines = _query_lines(text)
    cells_key = next(
        (k for k in ("cells", "detectionCells") if isinstance(doc.get(k), list)),
        None,
    )
    cells = tuple(
        Cell(
            name=c["name"],
            body=c["query"].strip(),
            first_line=lines.get((cells_key, i) if cells_key else (None, 0)),
            trigger=bool(c["trigger"]),
        )
        for i, c in enumerate(payload["cells"])
    )
    return Detection(path, payload["externalId"], payload["name"], cells)


# --------------------------------------------------------------------------
# Building the query for one cell
# --------------------------------------------------------------------------


def references(body: str, cell_names: Iterable[str]) -> list[str]:
    """Names of this detection's cells that `body` references, in order."""
    names = set(cell_names)
    seen: list[str] = []
    for match in _REFERENCE_RE.finditer(body):
        name = match.group(1)
        if name in names and name not in seen:
            seen.append(name)
    return seen


def _identifier(name: str, taken: set[str], prefix: str = "cell_") -> str:
    base = prefix + re.sub(r"[^A-Za-z0-9_]", "_", name)
    ident, n = base, 2
    while ident in taken:
        ident, n = f"{base}_{n}", n + 1
    taken.add(ident)
    return ident


@dataclass(frozen=True)
class _Swap:
    """One reference replaced by a name, to map a column back to the file."""

    line: int
    new_start: int
    new_end: int
    old_start: int
    # Length change of the line up to and including this swap.
    shift: int


def _cell_reference(token: str, idents: dict[str, str]) -> str | None:
    match = _REFERENCE_RE.fullmatch(token)
    return idents.get(match.group(1)) if match else None


def _substitute(
    body: str, idents: dict[str, str], aliases: dict[str, str] | None = None
) -> tuple[str, list[_Swap]]:
    """`body` with cell references, and selectors in `aliases`, swapped for names."""
    aliases = aliases or {}
    out: list[str] = []
    swaps: list[_Swap] = []
    for line_no, line in enumerate(body.split("\n")):
        parts: list[str] = []
        last = shift = 0
        for match in _SELECTOR_RE.finditer(line):
            token = match.group(0)
            name = _cell_reference(token, idents) or aliases.get(token)
            if name is None:
                continue
            parts.append(line[last : match.start()])
            new_start = match.start() + shift
            parts.append(name)
            shift += len(name) - len(token)
            swaps.append(
                _Swap(line_no, new_start, new_start + len(name), match.start(), shift)
            )
            last = match.end()
        parts.append(line[last:])
        out.append("".join(parts))
    return "\n".join(out), swaps


def _original_column(column: int, line: int, swaps: Iterable[_Swap]) -> int:
    position, shift = column - 1, 0
    for swap in swaps:
        if swap.line != line or position < swap.new_start:
            continue
        if position < swap.new_end:
            return swap.old_start + 1
        shift = swap.shift
    return position - shift + 1


def _other_selectors(body: str, cell_names: Iterable[str]) -> list[str]:
    """The `@` selectors of `body` that are not cells of this detection."""
    names = set(cell_names)
    out: list[str] = []
    for token in dict.fromkeys(_SELECTOR_RE.findall(body)):
        match = _REFERENCE_RE.fullmatch(token)
        if match and match.group(1) in names:
            continue
        out.append(token)
    return out


class CycleError(ValueError):
    pass


def dependency_order(detection: Detection) -> list[str]:
    """Every cell after the cells it references. Raises CycleError on a loop."""
    by_name = {c.name: c for c in detection.cells}
    order: list[str] = []
    state: dict[str, str] = {}

    def visit(name: str, path: list[str]) -> None:
        if state.get(name) == "done":
            return
        if state.get(name) == "open":
            loop = " -> ".join([*path[path.index(name) :], name])
            raise CycleError(f"cells reference each other in a loop: {loop}")
        state[name] = "open"
        for ref in references(by_name[name].body, by_name):
            visit(ref, [*path, name])
        state[name] = "done"
        order.append(name)

    for cell in detection.cells:
        visit(cell.name, [])
    return order


def _split_lets(body: str) -> tuple[list[str], str]:
    """The leading `let ...;` statements of a cell, and the rest."""
    lets: list[str] = []
    rest = body
    while re.match(r"let\s", rest):
        end = _statement_end(rest)
        if end < 0:
            break
        lets.append(rest[: end + 1].strip())
        rest = rest[end + 1 :].lstrip()
    return lets, rest


def _statement_end(text: str) -> int:
    depth = 0
    quote: str | None = None
    i = 0
    while i < len(text):
        ch = text[i]
        if quote:
            if ch == "\\":
                i += 1
            elif ch == quote:
                quote = None
        elif ch in "\"'":
            quote = ch
        elif text.startswith("//", i):
            newline = text.find("\n", i)
            i = len(text) if newline < 0 else newline
            continue
        elif ch in "([{":
            depth += 1
        elif ch in ")]}":
            depth -= 1
        elif ch == ";" and depth == 0:
            return i
        i += 1
    return -1


@dataclass(frozen=True)
class CellQuery:
    text: str
    # Lines before the cell's own body, to map an error back to the file.
    offset: int
    swaps: tuple[_Swap, ...] = ()


def build_query(detection: Detection, cell_name: str) -> CellQuery:
    by_name = {c.name: c for c in detection.cells}
    order = dependency_order(detection)
    needed: set[str] = set()

    def collect(name: str) -> None:
        for ref in references(by_name[name].body, by_name):
            if ref not in needed:
                needed.add(ref)
                collect(ref)

    collect(cell_name)
    taken: set[str] = set()
    idents = {name: _identifier(name, taken) for name in order if name in needed}
    # A list cannot mix a `let` name with a selector (`cell_a, @CloudTrail`
    # does not parse, `@a, @CloudTrail` does), so in a cell that uses other
    # cells, every other selector is named by a `let` too.
    aliases: dict[str, str] = {}
    for name in [*[n for n in order if n in needed], cell_name]:
        body = by_name[name].body
        if references(body, by_name):
            for token in _other_selectors(body, by_name):
                if token not in aliases and not token.startswith("@cells:"):
                    aliases[token] = _identifier(token[1:], taken, "src_")
    hoisted: list[str] = []
    lets = [f"let {alias} =\n{token}\n;" for token, alias in aliases.items()]
    for name in order:
        if name not in needed:
            continue
        inner, rest = _split_lets(by_name[name].body)
        hoisted += [s for s in inner if s not in hoisted]
        text, _ = _substitute(rest, idents, aliases if references(rest, by_name) else None)
        # `;` on its own line: a `//` comment on the cell's last line would
        # otherwise swallow it.
        lets.append(f"let {idents[name]} =\n{text}\n;")
    prefix = "\n".join([*hoisted, *lets])
    own = by_name[cell_name].body
    body, swaps = _substitute(own, idents, aliases if references(own, by_name) else None)
    if not prefix:
        return CellQuery(body, 0, tuple(swaps))
    return CellQuery(f"{prefix}\n{body}", prefix.count("\n") + 1, tuple(swaps))


# --------------------------------------------------------------------------
# Running
# --------------------------------------------------------------------------


@dataclass(frozen=True)
class RunOutcome:
    state: str
    code: str | None = None
    message: str | None = None


def parse_error(raw: str | None) -> tuple[str | None, str]:
    """(error_code_name, message) from the error string the API returns."""
    if not raw:
        return None, ""
    try:
        body = json.loads(raw)
    except ValueError:
        return None, raw
    if not isinstance(body, dict):
        return None, raw
    extra = body.get("extra_args") or {}
    message = (extra.get("query_error") if isinstance(extra, dict) else None) or body.get(
        "message"
    ) or raw
    return body.get("error_code_name"), str(message)


def _retry_after(error: VegaAPIError) -> float:
    waits = [
        (e.get("extensions") or {}).get("retryAfter")
        for e in error.errors
        if isinstance(e, dict)
    ]
    seconds = max((w for w in waits if isinstance(w, (int, float))), default=None)
    return min(seconds or DEFAULT_RETRY_AFTER_S, MAX_RETRY_AFTER_S)


def _patient(
    call: Callable[[], Any], sleep: Callable[[float], None]
) -> tuple[Any, float]:
    """`call()`, waiting out the tenant's rate limit. Returns the time waited."""
    waited = 0.0
    for attempt in range(MAX_RATE_LIMIT_WAITS + 1):
        try:
            return call(), waited
        except VegaAPIError as e:
            if RATE_LIMITED not in e.codes or attempt == MAX_RATE_LIMIT_WAITS:
                raise
            seconds = _retry_after(e)
            console.print(f"[dim]Rate limited by the tenant; waiting {seconds:g}s[/]")
            sleep(seconds)
            waited += seconds
    raise AssertionError("unreachable")


def run_query(
    client: VegaClient,
    query: str,
    timeframe: str,
    timeout_s: int,
    sleep: Callable[[float], None] = time.sleep,
    clock: Callable[[], float] = time.monotonic,
) -> RunOutcome:
    submitted, _ = _patient(
        lambda: client.run_federated_query(query, timeframe, timeout_s), sleep
    )
    if submitted is None:
        return RunOutcome("FAILED", None, "the query was not accepted")
    query_id, state = submitted.get("queryId"), submitted.get("state")
    error = submitted.get("error")
    deadline = clock() + timeout_s + CANCEL_GRACE_S
    polls = 0
    while state not in ("FINISHED", "FAILED", "CANCELLED"):
        if clock() >= deadline:
            try:
                _patient(lambda: client.cancel_federated_query(query_id), sleep)
            except VegaAPIError:
                pass
            return RunOutcome("TIMEOUT")
        sleep(POLL_DELAYS_S[min(polls, len(POLL_DELAYS_S) - 1)])
        polls += 1
        status, waited = _patient(lambda: client.federated_query_status(query_id), sleep)
        # Time spent waiting out the rate limit is not the query running long.
        deadline += waited
        if status is None:
            return RunOutcome("FAILED", None, "the query disappeared while running")
        state, error = status.get("state"), status.get("error")
    code, message = parse_error(error)
    return RunOutcome(state or "FAILED", code, message or None)


def _problems(
    message: str,
    query: CellQuery,
    cell: Cell,
    file_lines: list[str],
) -> list[Problem]:
    """One problem per error block, with its line mapped back to the file."""
    problems: list[Problem] = []
    for block in re.split(r"\n\s*\n", message.strip()):
        title = block.strip().split("\n", 1)[0].strip()
        if not title:
            continue
        help_match = _HELP_RE.search(block)
        line = column = None
        location = _LOCATION_RE.search(block)
        if location:
            body_line = int(location.group(1)) - query.offset
            body_lines = cell.body.split("\n")
            if 1 <= body_line <= len(body_lines) and cell.first_line is not None:
                line = cell.first_line + body_line - 1
                column = _original_column(
                    int(location.group(2)), body_line - 1, query.swaps
                )
                text = file_lines[line - 1] if line <= len(file_lines) else ""
                source = body_lines[body_line - 1]
                # The block indent, or `query: "`, is not part of the cell text.
                start = text.find(source) if source else -1
                if start >= 0:
                    column += start
            elif cell.first_line is not None:
                line = cell.first_line
        else:
            line = cell.first_line
        problems.append(
            Problem(title, help_match.group(1).strip() if help_match else None, line, column)
        )
    return problems


_NOT_FOUND_HELP = (
    "names are case-sensitive and match the data source's query name, "
    "e.g. @Okta-System-Logs"
)


def _not_found_problems(
    cell: Cell,
    cell_names: Iterable[str],
    exists: Callable[[str], bool | None],
) -> list[Problem]:
    """The API does not say which selector it could not find, so ask per selector."""
    selectors = [
        s for s in _other_selectors(cell.body, cell_names) if not s.startswith("@cells:")
    ]
    missing = [s for s in selectors if exists(s) is False]
    if missing:
        return [
            Problem(
                f"{s} does not exist in the tenant (not a data source, lookup "
                f"table or cell of this detection)",
                _NOT_FOUND_HELP,
                _line_of(cell, s),
            )
            for s in missing
        ]
    listed = ", ".join(selectors) or "the selectors in this cell"
    return [
        Problem(
            f"a data source or lookup table this cell reads does not exist in "
            f"the tenant: check {listed}",
            _NOT_FOUND_HELP,
            cell.first_line,
        )
    ]


def _line_of(cell: Cell, token: str) -> int | None:
    if cell.first_line is None:
        return None
    for i, line in enumerate(cell.body.split("\n")):
        if token in line:
            return cell.first_line + i
    return cell.first_line


def check_detection(
    client: VegaClient,
    detection: Detection,
    timeframe: str,
    timeout_s: int,
    run: Callable[..., RunOutcome] = run_query,
    known: dict[str, bool | None] | None = None,
) -> list[CellResult]:
    """`known` caches which selectors exist, across the detections of a run."""
    known = {} if known is None else known

    def exists(selector: str) -> bool | None:
        if selector not in known:
            try:
                outcome = run(client, f"{selector}\n| take 1", timeframe, timeout_s)
            except VegaAPIError:
                outcome = RunOutcome("FAILED")
            known[selector] = (
                False
                if outcome.code == QUERY_TARGET_NOT_FOUND
                else True if outcome.state == "FINISHED" else None
            )
        return known[selector]

    file_lines = detection.path.read_text(encoding="utf-8").split("\n")
    by_name = {c.name: c for c in detection.cells}
    try:
        order = dependency_order(detection)
    except CycleError as e:
        trigger = next(c for c in detection.cells if c.trigger)
        return [
            CellResult(detection, trigger, Verdict.FAIL, [Problem(str(e), line=trigger.first_line)])
        ]

    results: dict[str, CellResult] = {}
    for name in order:
        cell = by_name[name]
        failed_refs = [
            r
            for r in references(cell.body, by_name)
            if results[r].verdict in (Verdict.FAIL, Verdict.SKIPPED)
        ]
        if failed_refs:
            results[name] = CellResult(
                detection,
                cell,
                Verdict.SKIPPED,
                [Problem(f"not checked: it uses {', '.join(failed_refs)}, which failed")],
            )
            continue
        query = build_query(detection, name)
        try:
            outcome = run(client, query.text, timeframe, timeout_s)
        except VegaAPIError as e:
            # A key without QueryRead fails every pull request until it is
            # fixed, which is louder than a warning nobody opens.
            verdict = Verdict.FAIL if ACCESS_DENIED in e.codes else Verdict.WARN
            results[name] = CellResult(
                detection, cell, verdict, [Problem(f"could not run the query: {e}")]
            )
            continue
        results[name] = _result(detection, cell, outcome, query, file_lines, exists)
    return [results[c.name] for c in detection.cells]


def _result(
    detection: Detection,
    cell: Cell,
    outcome: RunOutcome,
    query: CellQuery,
    file_lines: list[str],
    exists: Callable[[str], bool | None],
) -> CellResult:
    if outcome.state == "FINISHED":
        return CellResult(detection, cell, Verdict.PASS)
    if outcome.state in ("TIMEOUT", "CANCELLED") or outcome.code == QUERY_TIMEOUT:
        return CellResult(
            detection,
            cell,
            Verdict.WARN,
            [Problem("did not finish in time, so it was cancelled; not checked")],
        )
    if outcome.code == QUERY_TARGET_NOT_FOUND:
        names = [c.name for c in detection.cells]
        return CellResult(
            detection,
            cell,
            Verdict.FAIL,
            _not_found_problems(cell, names, exists),
            outcome.code,
        )
    if outcome.code == UNKNOWN_CELL_REFERENCE:
        names = [c.name for c in detection.cells]
        outside = [
            s for s in _other_selectors(cell.body, names) if s.startswith("@cells:")
        ]
        return CellResult(
            detection,
            cell,
            Verdict.FAIL,
            [
                Problem(
                    f"{s} is not a cell of this detection and the tenant has no cell "
                    f"with that reference",
                    "write a cell of this file as @Name; @cells:<ref>/Name only "
                    "points at a cell already saved in Vega",
                    _line_of(cell, s),
                )
                for s in outside
            ]
            or [Problem(outcome.message or outcome.code, line=cell.first_line)],
            outcome.code,
        )
    if outcome.code in _AUTHOR_ERROR_CODES:
        problems = _problems(outcome.message or outcome.code or "", query, cell, file_lines)
        return CellResult(
            detection,
            cell,
            Verdict.FAIL,
            problems or [Problem(outcome.message or str(outcome.code), line=cell.first_line)],
            outcome.code,
        )
    detail = outcome.message or outcome.state
    return CellResult(
        detection,
        cell,
        Verdict.WARN,
        [Problem(f"the tenant could not run the query ({outcome.code or outcome.state}): {detail}")],
        outcome.code,
    )


# --------------------------------------------------------------------------
# Reporting
# --------------------------------------------------------------------------


def _escape_data(text: str) -> str:
    return text.replace("%", "%25").replace("\r", "%0D").replace("\n", "%0A")


def _escape_property(text: str) -> str:
    return _escape_data(text).replace(":", "%3A").replace(",", "%2C")


# GitHub keeps only this many annotations of each level per step.
MAX_ANNOTATIONS = 10


def annotations(results: Iterable[CellResult]) -> list[str]:
    """GitHub workflow commands: each one shows on the file in the PR diff."""
    by_level: dict[str, list[str]] = {"error": [], "warning": []}
    for r in results:
        if r.verdict not in (Verdict.FAIL, Verdict.WARN):
            continue
        level = "error" if r.verdict is Verdict.FAIL else "warning"
        for p in r.problems:
            props = [f"file={_escape_property(str(r.detection.path))}"]
            if p.line is not None:
                props.append(f"line={p.line}")
            if p.column is not None:
                props.append(f"col={p.column}")
            props.append(
                "title=" + _escape_property(f"KQL: {r.detection.name} / cell {r.cell.name}")
            )
            text = p.message if not p.help else f"{p.message}\nHelp: {p.help}"
            by_level[level].append(f"::{level} {','.join(props)}::{_escape_data(text)}")
    out: list[str] = []
    for level, lines in by_level.items():
        if len(lines) > MAX_ANNOTATIONS:
            more = len(lines) - (MAX_ANNOTATIONS - 1)
            lines = [
                *lines[: MAX_ANNOTATIONS - 1],
                f"::{level} title=KQL check::{more} more; the job Summary lists every one",
            ]
        out += lines
    return out


_ICONS = {
    Verdict.PASS: "✅",
    Verdict.FAIL: "❌",
    Verdict.WARN: "⚠️",
    Verdict.SKIPPED: "⏭️",
}


def _location(r: CellResult, p: Problem) -> str:
    where = str(r.detection.path)
    if p.line is not None:
        where += f":{p.line}"
        if p.column is not None:
            where += f":{p.column}"
    return where


def step_summary(results: list[CellResult], timeframe: str) -> str:
    fails = [r for r in results if r.verdict is Verdict.FAIL]
    warns = [r for r in results if r.verdict is Verdict.WARN]
    if not results:
        return "## ✅ KQL: no detection files changed\n"
    if fails:
        header = f"## ❌ KQL check failed: {len(fails)} of {len(results)} cell(s)"
    elif warns:
        header = f"## ⚠️ KQL check passed with {len(warns)} cell(s) not checked"
    else:
        header = f"## ✅ KQL check passed: {len(results)} cell(s)"
    lines = [
        header,
        "",
        f"Each cell ran on the tenant over the last `{timeframe}`. "
        "A cell that references another runs with that cell inlined.",
        "",
        "| | Detection | Cell | Detail |",
        "|---|---|---|---|",
    ]
    for r in results:
        detail = r.summary.replace("|", "\\|").replace("\n", " ")
        lines.append(
            f"| {_ICONS[r.verdict]} | {r.detection.name} (`{r.detection.path}`) "
            f"| {r.cell.name} | {detail} |"
        )
    for r in fails:
        file_lines = r.detection.path.read_text(encoding="utf-8").split("\n")
        for p in r.problems:
            lines += ["", "```text", f"{_location(r, p)}  {p.message}"]
            if p.line is not None and p.line <= len(file_lines):
                lines.append(f"{p.line:>5} | {file_lines[p.line - 1]}")
                if p.column is not None:
                    lines.append(f"{'':>5} | {' ' * (p.column - 1)}^")
            if p.help:
                lines.append(f"Help: {p.help}")
            lines.append("```")
    return "\n".join(lines) + "\n"


def _table(results: list[CellResult]) -> Table:
    t = Table(show_header=True, header_style="bold")
    t.add_column("")
    t.add_column("File")
    t.add_column("Cell")
    t.add_column("Detail")
    colours = {
        Verdict.PASS: "green",
        Verdict.FAIL: "red",
        Verdict.WARN: "yellow",
        Verdict.SKIPPED: "dim",
    }
    for r in results:
        t.add_row(
            f"[{colours[r.verdict]}]{r.verdict.value}[/]",
            str(r.detection.path),
            r.cell.name,
            "; ".join(f"{_location(r, p)} {p.message}" for p in r.problems),
        )
    return t


def _write_step_summary(text: str) -> None:
    summary_file = os.environ.get("GITHUB_STEP_SUMMARY")
    if not summary_file:
        return
    try:
        with open(summary_file, "a", encoding="utf-8") as fh:
            fh.write(text)
    except OSError as e:
        console.print(f"[yellow]warning:[/] could not write step summary: {e}")


# --------------------------------------------------------------------------
# Command
# --------------------------------------------------------------------------


def _paths(detections_dir: Path, base_sha: str | None) -> list[Path]:
    """Repository-relative paths, the form a GitHub annotation needs."""
    detections_dir = detections_dir.resolve()
    if base_sha is not None:
        edited, _ = changed_paths(base_sha, detections_dir)
        return edited
    root = Path.cwd()
    return [
        f.relative_to(root) if f.is_relative_to(root) else f
        for f in yaml_files(detections_dir)
    ]


@click.command(help="Run the KQL of changed detections on the tenant.")
@click.option(
    "--detections-dir",
    type=click.Path(exists=True, file_okay=False, path_type=Path),
    default="./detections",
    show_default=True,
)
@click.option(
    "--base-sha",
    help="Check only the detection files changed since this commit. "
    "Without it every detection file is checked.",
)
@click.option("--timeframe", default=DEFAULT_TIMEFRAME, show_default=True)
@click.option("--timeout", "timeout_s", default=DEFAULT_TIMEOUT_S, show_default=True)
@click.option(
    "--tenant-url",
    default=lambda: os.environ.get("VEGA_TENANT_URL") or DEFAULT_TENANT_URL,
    show_default=DEFAULT_TENANT_URL,
)
@click.option("--access-key", envvar="VEGA_ACCESS_KEY")
@click.option("--access-key-id", envvar="VEGA_ACCESS_KEY_ID")
@click.option("--scope-id", envvar="VEGA_SCOPE_ID")
def main(
    detections_dir: Path,
    base_sha: str | None,
    timeframe: str,
    timeout_s: int,
    tenant_url: str,
    access_key: str | None,
    access_key_id: str | None,
    scope_id: str | None,
) -> None:
    if not access_key:
        console.print(
            "[red]ERROR:[/] missing access key. Set VEGA_ACCESS_KEY or pass --access-key."
        )
        sys.exit(2)

    detections: list[Detection] = []
    for path in _paths(detections_dir, base_sha):
        try:
            detections.append(load_detection(path))
        except (ValueError, yaml.YAMLError) as e:
            # The schema check in the same workflow reports it.
            console.print(f"[dim]{path}: skipped, the file is not valid: {e}[/]")

    if not detections:
        console.print("[dim]No detection to check.[/]")
        _write_step_summary(step_summary([], timeframe))
        sys.exit(0)

    console.print(f"[cyan]Authenticating to[/] {tenant_url}")
    try:
        client = VegaClient.login(
            access_key, tenant_url=tenant_url, access_key_id=access_key_id, scope_id=scope_id
        )
    except RuntimeError as e:
        print(f"::error title=KQL check::{_escape_data(f'could not log in to {tenant_url}: {e}')}")
        sys.exit(1)

    results: list[CellResult] = []
    known: dict[str, bool | None] = {}
    for detection in detections:
        console.print(f"[cyan]Checking[/] {detection.path} ({len(detection.cells)} cell(s))")
        results += check_detection(client, detection, timeframe, timeout_s, known=known)

    for line in annotations(results):
        print(line)
    console.print(_table(results))
    _write_step_summary(step_summary(results, timeframe))
    sys.exit(1 if any(r.verdict is Verdict.FAIL for r in results) else 0)


if __name__ == "__main__":
    main()
