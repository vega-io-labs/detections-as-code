from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from scripts.client import VegaAPIError
from scripts.kql_validate import (
    CycleError,
    RunOutcome,
    Verdict,
    annotations,
    build_query,
    check_detection,
    dependency_order,
    load_detection,
    parse_error,
    references,
    run_query,
    step_summary,
)

# Error strings exactly as runFederatedQuery returned them on a live tenant.
WHER_ERROR = json.dumps(
    {
        "error_code": "E000000001",
        "error_code_name": "INVALID_QUERY",
        "extra_args": {
            "query_error": "unknown query operator 'wher'\n   ╭─[ query:2:3 ]\n   │\n 2 │ | wher event_name == \"x\"\n   │   ──┬─  \n   │     ╰─── unknown query operator 'wher'\n   │ \n   │ Help: did you mean 'where'?\n───╯"
        },
        "message": "unknown query operator 'wher'",
        "trace_id": 1,
    }
)
TWO_ERRORS = json.dumps(
    {
        "error_code_name": "INVALID_QUERY",
        "extra_args": {
            "query_error": "unknown query operator 'projct'\n   ╭─[ query:2:3 ]\n   │\n 2 │ | projct actor.user.email\n   │   ───┬──  \n   │      ╰──── unknown query operator 'projct'\n   │ \n   │ Help: did you mean 'project'?\n───╯\n\nmissing '|' before 'where'\n   ╭─[ query:3:3 ]\n   │\n 3 │ | where isnotempty(actor.user.email)\n   │   ──┬──  \n   │     ╰──── missing '|' before 'where'\n───╯"
        },
    }
)
NOT_FOUND = json.dumps(
    {
        "error_code_name": "QUERY_TARGET_NOT_FOUND",
        "extra_args": None,
        "message": "The queried data source is not available. Please contact support if the issue persists.",
    }
)

SINGLE = """\
id: "019e0000-0000-7000-8000-000000000001"
name: "Root login"
severity: 4
state: "enabled"
frequencyCron: "5m"
lookBackSeconds: 300
query: |-
  @CloudTrail
  | wher event_name == "x"
"""

CHAIN = """\
id: "019e0000-0000-7000-8000-000000000002"
name: "Tor login then AWS write"
severity: 4
state: "enabled"
frequencyCron: "10m"
lookBackSeconds: 3600
cells:
  - name: "tor-okta-logins"
    query: |-
      @Okta-System-Logs
      | where actor.user.email != "svc@corp.com" // service account
      | join kind=inner (
          @lookup_tables:tor-exits/Tor-Exit-Nodes
        ) on $left.src_endpoint.ip == $right.ip_address
  - name: "aws-writes"
    query: |-
      let noisy = dynamic(["GetCallerIdentity"]);
      @cells:W4Q4Z/tor-okta-logins
      | join kind=inner (@CloudTrail | where event_name !in (noisy)) on actor.user.email
  - name: "trigger"
    trigger: true
    query: |-
      @aws-writes
      | where event_source in ("iam.amazonaws.com")
"""

UNION = """\
id: "019e0000-0000-7000-8000-000000000003"
name: "Credential tools"
severity: 3
state: "enabled"
frequencyCron: "5m"
lookBackSeconds: 300
cells:
  - name: "tool-execution"
    query: "@EDR-Events | where file.path has 'mimikatz.exe'"
  - name: "lsa-dump"
    query: "@EDR-Events | where process.cmd_line contains 'lsadump::sam'"
  - name: "trigger"
    trigger: true
    query: |-
      @tool-execution,
      @lsa-dump
"""


def _write(tmp_path: Path, text: str, name: str = "d.yaml") -> Path:
    path = tmp_path / name
    path.write_text(text, encoding="utf-8")
    return path


class ScriptedRun:
    """Stands in for run_query: answers by a substring of the query text."""

    def __init__(self, answers: dict[str, RunOutcome] | None = None) -> None:
        self.answers = answers or {}
        self.queries: list[str] = []

    def __call__(self, client: Any, query: str, timeframe: str, timeout_s: int) -> RunOutcome:
        self.queries.append(query)
        for needle, outcome in self.answers.items():
            if needle in query.split("\n")[-1] or query.startswith(needle):
                return outcome
        return RunOutcome("FINISHED")


def _failed(raw: str) -> RunOutcome:
    code, message = parse_error(raw)
    return RunOutcome("FAILED", code, message)


# --------------------------------------------------------------------------
# Reading and building
# --------------------------------------------------------------------------


def test_single_cell_query_maps_to_its_file_lines(tmp_path):
    detection = load_detection(_write(tmp_path, SINGLE))
    assert [c.name for c in detection.cells] == ["trigger"]
    assert detection.cells[0].first_line == 8


def test_multi_cell_first_lines_point_at_each_query(tmp_path):
    path = _write(tmp_path, CHAIN)
    detection = load_detection(path)
    lines = path.read_text().split("\n")
    for cell in detection.cells:
        assert lines[cell.first_line - 1].strip() == cell.body.split("\n")[0].strip()


def test_quoted_one_line_queries_have_a_line(tmp_path):
    path = _write(tmp_path, UNION)
    detection = load_detection(path)
    assert detection.cells[0].first_line == 9


def test_references_ignore_emails_lookups_and_data_sources():
    body = (
        '@Okta-System-Logs | where x == "a@tool-execution.com"\n'
        "| join (@lookup_tables:tor/T) on ip\n"
        "| join (@cells:AB12/lsa-dump) on h\n"
        "| join (@tool-execution) on h"
    )
    assert references(body, ["tool-execution", "lsa-dump", "Okta-System-Logs-x"]) == [
        "lsa-dump",
        "tool-execution",
    ]


def test_dependency_order_puts_referenced_cells_first(tmp_path):
    detection = load_detection(_write(tmp_path, CHAIN))
    assert dependency_order(detection) == ["tor-okta-logins", "aws-writes", "trigger"]


def test_a_loop_between_cells_is_reported(tmp_path):
    loop = CHAIN.replace("@Okta-System-Logs", "@trigger")
    detection = load_detection(_write(tmp_path, loop))
    with pytest.raises(CycleError, match="tor-okta-logins -> trigger -> aws-writes -> tor-okta-logins"):
        dependency_order(detection)


def test_a_cell_without_references_runs_as_written(tmp_path):
    detection = load_detection(_write(tmp_path, CHAIN))
    query = build_query(detection, "tor-okta-logins")
    assert query.text == detection.cells[0].body
    assert query.offset == 0


def test_referenced_cells_are_inlined_as_lets_with_their_own_lets_lifted(tmp_path):
    detection = load_detection(_write(tmp_path, CHAIN))
    query = build_query(detection, "trigger")
    assert query.text == (
        'let noisy = dynamic(["GetCallerIdentity"]);\n'
        "let src_CloudTrail =\n"
        "@CloudTrail\n"
        ";\n"
        "let cell_tor_okta_logins =\n"
        "@Okta-System-Logs\n"
        '| where actor.user.email != "svc@corp.com" // service account\n'
        "| join kind=inner (\n"
        "    @lookup_tables:tor-exits/Tor-Exit-Nodes\n"
        "  ) on $left.src_endpoint.ip == $right.ip_address\n"
        ";\n"
        "let cell_aws_writes =\n"
        "cell_tor_okta_logins\n"
        "| join kind=inner (src_CloudTrail | where event_name !in (noisy)) on actor.user.email\n"
        ";\n"
        "cell_aws_writes\n"
        '| where event_source in ("iam.amazonaws.com")'
    )
    assert query.text.split("\n")[query.offset] == "cell_aws_writes"


def test_a_union_trigger_keeps_its_comma_form(tmp_path):
    detection = load_detection(_write(tmp_path, UNION))
    query = build_query(detection, "trigger")
    assert query.text.endswith("cell_tool_execution,\ncell_lsa_dump")
    assert "src_" not in query.text


def test_a_data_source_listed_next_to_a_cell_is_named_by_a_let(tmp_path):
    # Live: `cell_a, @Okta-System-Logs` does not parse; `cell_a, src_x` does.
    text = UNION.replace("@lsa-dump", "@Okta-System-Logs")
    detection = load_detection(_write(tmp_path, text))
    query = build_query(detection, "trigger")
    assert "let src_Okta_System_Logs =\n@Okta-System-Logs\n;" in query.text
    assert query.text.endswith("cell_tool_execution,\nsrc_Okta_System_Logs")


def test_a_cell_without_references_keeps_its_selectors(tmp_path):
    detection = load_detection(_write(tmp_path, UNION))
    assert build_query(detection, "lsa-dump").text == detection.cells[1].body


# --------------------------------------------------------------------------
# Running and verdicts
# --------------------------------------------------------------------------


def test_a_syntax_error_lands_on_the_file_line_and_column(tmp_path):
    path = _write(tmp_path, SINGLE)
    run = ScriptedRun({"wher": _failed(WHER_ERROR)})
    [result] = check_detection(None, load_detection(path), "PT15M", 60, run)

    assert result.verdict is Verdict.FAIL
    [problem] = result.problems
    assert problem.message == "unknown query operator 'wher'"
    assert problem.help == "did you mean 'where'?"
    assert (problem.line, problem.column) == (9, 5)
    assert path.read_text().split("\n")[8][4:8] == "wher"


def test_a_column_after_a_swapped_reference_maps_back_to_the_file(tmp_path):
    text = CHAIN.replace(
        '      @aws-writes\n      | where event_source in ("iam.amazonaws.com")',
        "      @aws-writes | whre isnotempty(event_source)",
    )
    path = _write(tmp_path, text)
    detection = load_detection(path)
    trigger = build_query(detection, "trigger")
    assert trigger.text.split("\n")[-1] == "cell_aws_writes | whre isnotempty(event_source)"
    error = WHER_ERROR.replace("query:2:3", f"query:{trigger.offset + 1}:19")
    run = ScriptedRun({"whre": _failed(error)})
    problem = check_detection(None, detection, "PT15M", 60, run)[2].problems[0]

    line = path.read_text().split("\n")[problem.line - 1]
    assert line[problem.column - 1 :].startswith("whre")


def test_a_column_in_a_quoted_one_line_query_maps_past_the_key(tmp_path):
    text = SINGLE.replace('query: |-\n  @CloudTrail\n  | wher event_name == "x"\n', 'query: "@CloudTrail | sortt by x"\n')
    path = _write(tmp_path, text)
    error = WHER_ERROR.replace("query:2:3", "query:1:15")
    run = ScriptedRun({"sortt": _failed(error)})
    [result] = check_detection(None, load_detection(path), "PT15M", 60, run)
    problem = result.problems[0]
    line = path.read_text().split("\n")[problem.line - 1]
    assert line[problem.column - 1 :].startswith("sortt")


def test_each_error_block_becomes_its_own_problem(tmp_path):
    text = SINGLE.replace('| wher event_name == "x"', "| projct actor.user.email\n  | where isnotempty(actor.user.email)")
    run = ScriptedRun({"isnotempty": _failed(TWO_ERRORS)})
    [result] = check_detection(None, load_detection(_write(tmp_path, text)), "PT15M", 60, run)
    assert [p.line for p in result.problems] == [9, 10]


def test_an_error_in_the_trigger_is_mapped_past_the_inlined_cells(tmp_path):
    path = _write(tmp_path, CHAIN)
    detection = load_detection(path)
    trigger = build_query(detection, "trigger")
    # The engine counts lines in the query it ran, lets included.
    error = WHER_ERROR.replace("query:2:3", f"query:{trigger.offset + 2}:3")
    run = ScriptedRun({'event_source in': _failed(error)})
    results = check_detection(None, detection, "PT15M", 60, run)

    assert [r.verdict for r in results] == [Verdict.PASS, Verdict.PASS, Verdict.FAIL]
    assert results[2].problems[0].line == detection.cells[2].first_line + 1


def test_cells_run_one_at_a_time_in_dependency_order(tmp_path):
    run = ScriptedRun()
    results = check_detection(None, load_detection(_write(tmp_path, CHAIN)), "PT15M", 60, run)
    assert [r.verdict for r in results] == [Verdict.PASS] * 3
    assert [q.split("\n")[-1] for q in run.queries] == [
        "  ) on $left.src_endpoint.ip == $right.ip_address",
        "| join kind=inner (src_CloudTrail | where event_name !in (noisy)) on actor.user.email",
        '| where event_source in ("iam.amazonaws.com")',
    ]


def test_cells_using_a_failed_cell_are_not_run(tmp_path):
    run = ScriptedRun({"$right.ip_address": _failed(WHER_ERROR)})
    results = check_detection(None, load_detection(_write(tmp_path, CHAIN)), "PT15M", 60, run)
    assert [r.verdict for r in results] == [Verdict.FAIL, Verdict.SKIPPED, Verdict.SKIPPED]
    assert len(run.queries) == 1
    assert "tor-okta-logins, which failed" in results[1].summary


def test_a_missing_data_source_names_the_selectors_of_the_cell(tmp_path):
    run = ScriptedRun({"$right.ip_address": _failed(NOT_FOUND)})
    [first, *_] = check_detection(None, load_detection(_write(tmp_path, CHAIN)), "PT15M", 60, run)
    assert first.verdict is Verdict.FAIL
    assert "@Okta-System-Logs, @lookup_tables:tor-exits/Tor-Exit-Nodes" in first.summary


def test_a_missing_selector_is_named_by_asking_for_each_one(tmp_path):
    run = ScriptedRun(
        {
            "$right.ip_address": _failed(NOT_FOUND),
            "@lookup_tables:tor-exits/Tor-Exit-Nodes": _failed(NOT_FOUND),
        }
    )
    path = _write(tmp_path, CHAIN)
    [first, *_] = check_detection(None, load_detection(path), "PT15M", 60, run)
    [problem] = first.problems
    assert problem.message.startswith("@lookup_tables:tor-exits/Tor-Exit-Nodes does not exist")
    assert "@lookup_tables" in path.read_text().split("\n")[problem.line - 1]


def test_selectors_are_asked_about_once_per_run(tmp_path):
    run = ScriptedRun({"$right.ip_address": _failed(NOT_FOUND)})
    known: dict[str, bool | None] = {}
    for name in ("a.yaml", "b.yaml"):
        check_detection(None, load_detection(_write(tmp_path, CHAIN, name)), "PT15M", 60, run, known)
    probes = [q for q in run.queries if q.endswith("| take 1")]
    assert probes == ["@Okta-System-Logs\n| take 1", "@lookup_tables:tor-exits/Tor-Exit-Nodes\n| take 1"]


def test_a_loop_fails_the_trigger_without_running_anything(tmp_path):
    run = ScriptedRun()
    loop = CHAIN.replace("@Okta-System-Logs", "@trigger")
    [result] = check_detection(None, load_detection(_write(tmp_path, loop)), "PT15M", 60, run)
    assert result.verdict is Verdict.FAIL and result.cell.trigger
    assert run.queries == []


def test_an_unknown_cell_reference_names_the_reference(tmp_path):
    text = SINGLE.replace('  @CloudTrail\n  | wher event_name == "x"', "  @cells:ZZZZZ/Elsewhere\n  | where isnotempty(x)")
    run = ScriptedRun({"@cells:ZZZZZ": RunOutcome("FAILED", "UNKNOWN_CELL_REFERENCE_IN_QUERY", "Unknown cell referenced in query")})
    [result] = check_detection(None, load_detection(_write(tmp_path, text)), "PT15M", 60, run)
    [problem] = result.problems
    assert result.verdict is Verdict.FAIL
    assert problem.message.startswith("@cells:ZZZZZ/Elsewhere is not a cell of this detection")
    assert problem.line == 8


def test_an_error_without_a_location_lands_on_the_cell(tmp_path):
    run = ScriptedRun({"wher": RunOutcome("FAILED", "INVALID_QUERY", "something is wrong")})
    [result] = check_detection(None, load_detection(_write(tmp_path, SINGLE)), "PT15M", 60, run)
    assert result.problems[0].line == 8


@pytest.mark.parametrize(
    "outcome,verdict",
    [
        (RunOutcome("TIMEOUT"), Verdict.WARN),
        (RunOutcome("CANCELLED"), Verdict.WARN),
        (RunOutcome("FAILED", "QUERY_TIMEOUT", "query exceeded time limit"), Verdict.WARN),
        (RunOutcome("FAILED", "INTERNAL_SERVER_ERROR", "boom"), Verdict.WARN),
        (RunOutcome("FAILED", "UNKNOWN_CELL_REFERENCE_IN_QUERY", "referenced cell no longer exists"), Verdict.FAIL),
    ],
)
def test_only_author_errors_fail_the_check(tmp_path, outcome, verdict):
    run = ScriptedRun({"wher": outcome})
    [result] = check_detection(None, load_detection(_write(tmp_path, SINGLE)), "PT15M", 60, run)
    assert result.verdict is verdict


@pytest.mark.parametrize(
    "codes,verdict",
    [(["ACCESS_DENIED"], Verdict.FAIL), (["RATE_LIMITED"], Verdict.WARN)],
)
def test_api_errors_fail_only_for_a_missing_permission(tmp_path, codes, verdict):
    errors = [{"extensions": {"error_code_name": c}} for c in codes]

    def run(*_: Any) -> RunOutcome:
        raise VegaAPIError("GraphQL errors", errors, "QueryRead")

    [result] = check_detection(None, load_detection(_write(tmp_path, SINGLE)), "PT15M", 60, run)
    assert result.verdict is verdict


class FakeClient:
    def __init__(self, states: list[dict[str, Any] | None], submitted: dict[str, Any] | None = None) -> None:
        self.states = states
        self.submitted = submitted if submitted is not None else {"queryId": "q1", "state": "QUEUED", "error": None}
        self.calls: list[tuple[str, Any]] = []

    def run_federated_query(self, query: str, timeframe: str, timeout_s: int | None = None):
        self.calls.append(("run", (timeframe, timeout_s)))
        return self.submitted

    def federated_query_status(self, query_id: str):
        self.calls.append(("status", query_id))
        return self.states.pop(0)

    def cancel_federated_query(self, query_id: str) -> str:
        self.calls.append(("cancel", query_id))
        return query_id


def test_run_query_polls_until_the_query_ends():
    client = FakeClient([{"state": "RUNNING"}, {"state": "FAILED", "error": WHER_ERROR}])
    outcome = run_query(client, "q", "PT15M", 60, sleep=lambda _: None)
    assert (outcome.state, outcome.code) == ("FAILED", "INVALID_QUERY")
    assert outcome.message.startswith("unknown query operator 'wher'")
    assert client.calls[0] == ("run", ("PT15M", 60))


def test_run_query_cancels_a_query_that_runs_past_the_timeout():
    ticks = iter(range(0, 1000, 50))
    client = FakeClient([{"state": "RUNNING"}] * 10)
    outcome = run_query(client, "q", "PT15M", 60, sleep=lambda _: None, clock=lambda: next(ticks))
    assert outcome.state == "TIMEOUT"
    assert client.calls[-1] == ("cancel", "q1")


def test_run_query_reads_a_failure_returned_at_submit():
    client = FakeClient([], {"queryId": "q1", "state": "FAILED", "error": NOT_FOUND})
    outcome = run_query(client, "q", "PT15M", 60, sleep=lambda _: None)
    assert outcome.code == "QUERY_TARGET_NOT_FOUND"
    assert [c[0] for c in client.calls] == ["run"]


def _rate_limited(retry_after: int | None = 17) -> VegaAPIError:
    extensions: dict[str, Any] = {"error_code_name": "REQUEST_RATE_LIMITED"}
    if retry_after is not None:
        extensions["retryAfter"] = retry_after
    return VegaAPIError("GraphQL errors", [{"message": "Rate limit exceeded", "extensions": extensions}])


class RateLimitedClient(FakeClient):
    def __init__(self, limits: dict[str, int], states: list[dict[str, Any] | None]) -> None:
        super().__init__(states)
        self.limits = limits

    def _maybe_limit(self, call: str) -> None:
        if self.limits.get(call, 0) > 0:
            self.limits[call] -= 1
            raise _rate_limited()

    def run_federated_query(self, query: str, timeframe: str, timeout_s: int | None = None):
        self._maybe_limit("run")
        return super().run_federated_query(query, timeframe, timeout_s)

    def federated_query_status(self, query_id: str):
        self._maybe_limit("status")
        return super().federated_query_status(query_id)


def test_run_query_waits_out_the_rate_limit_as_the_tenant_asks():
    waits: list[float] = []
    client = RateLimitedClient({"run": 1, "status": 2}, [{"state": "FINISHED"}])
    outcome = run_query(client, "q", "PT15M", 60, sleep=waits.append)
    assert outcome.state == "FINISHED"
    assert [w for w in waits if w == 17] == [17, 17, 17]


def test_waiting_out_the_rate_limit_does_not_time_the_query_out():
    now = [0.0]

    def sleep(seconds: float) -> None:
        now[0] += seconds

    client = RateLimitedClient({"status": 5}, [{"state": "FINISHED"}])
    outcome = run_query(client, "q", "PT15M", 30, sleep=sleep, clock=lambda: now[0])
    assert outcome.state == "FINISHED"


def test_a_rate_limit_that_does_not_lift_is_a_warning(tmp_path):
    def run(*_: Any) -> RunOutcome:
        raise _rate_limited()

    [result] = check_detection(None, load_detection(_write(tmp_path, SINGLE)), "PT15M", 60, run)
    assert result.verdict is Verdict.WARN


def test_a_retry_after_is_capped_and_has_a_default():
    from scripts.kql_validate import _retry_after

    assert _retry_after(_rate_limited(600)) == 60
    assert _retry_after(_rate_limited(None)) == 10


def test_parse_error_keeps_a_non_json_error_as_text():
    assert parse_error("engine down") == (None, "engine down")
    assert parse_error(None) == (None, "")


# --------------------------------------------------------------------------
# Reporting
# --------------------------------------------------------------------------


def test_annotations_point_at_the_file_line_and_escape_the_text(tmp_path):
    path = _write(tmp_path, SINGLE)
    run = ScriptedRun({"wher": _failed(WHER_ERROR)})
    results = check_detection(None, load_detection(path), "PT15M", 60, run)
    [line] = annotations(results)
    assert line.startswith(f"::error file={path},line=9,col=5,title=KQL%3A Root login / cell trigger::")
    assert line.endswith("unknown query operator 'wher'%0AHelp: did you mean 'where'?")


def test_annotations_stop_at_the_github_limit_with_a_pointer_to_the_summary(tmp_path):
    run = ScriptedRun({"wher": _failed(WHER_ERROR)})
    results = []
    for i in range(12):
        path = _write(tmp_path, SINGLE.replace("000000000001", f"0000000000{i + 10}"), f"d{i}.yaml")
        results += check_detection(None, load_detection(path), "PT15M", 60, run)
    lines = annotations(results)
    assert len(lines) == 10
    assert lines[-1] == "::error title=KQL check::3 more; the job Summary lists every one"


def test_passing_cells_have_no_annotation(tmp_path):
    results = check_detection(None, load_detection(_write(tmp_path, UNION)), "PT15M", 60, ScriptedRun())
    assert annotations(results) == []


def test_step_summary_shows_the_failing_file_line_with_a_caret(tmp_path):
    path = _write(tmp_path, SINGLE)
    run = ScriptedRun({"wher": _failed(WHER_ERROR)})
    summary = step_summary(check_detection(None, load_detection(path), "PT15M", 60, run), "PT15M")
    assert summary.startswith("## ❌ KQL check failed: 1 of 1 cell(s)")
    assert f"{path}:9:5  unknown query operator 'wher'" in summary
    assert '    9 |   | wher event_name == "x"\n      |     ^' in summary
    assert "Help: did you mean 'where'?" in summary
