# AGENTS.md

Guidance for AI coding assistants (Claude Code, Cursor, Copilot, etc.) operating in this repository.

## Repository purpose

Detection-as-Code template for Vega customers. YAML detections under `detections/` are synchronised to the customer's Vega tenant on every merge to `main`. The sync engine resides in `scripts/`; the GitHub Actions workflows reside in `.github/workflows/`.

## Authoring a new detection

1. Copy [`docs/detection.template.yaml`](docs/detection.template.yaml) into `detections/<category>/<name>.yaml`. The subdirectory layout is for organisational use only; the sync engine reads recursively.
2. Specify every required field explicitly (no silent defaults): `id`, `name`, `severity`, `state`, `frequencyCron`, `lookBackSeconds`, and either `query` (single-cell) or `cells` (multi-cell).
3. Generate `id` as a UUID v7. Once synced, the id is reserved permanently in the tenant and must not be reused.
4. Set `state: "test_mode"` for new detections until they have been validated against production data.

## YAML schema reference

The authoritative reference is [`docs/fields.md`](docs/fields.md). Key constraints:

- Severity: int `1-4` (`1=LOW, 2=MEDIUM, 3=HIGH, 4=CRITICAL`).
- State: `enabled | disabled | test_mode`.
- `id` regex: `^[a-z0-9][a-z0-9._-]{0,127}$` (UUID v7 satisfies this).
- `name`: 1-200 characters.
- `frequencyCron`: an hour/minute interval (`5m`, `1h`, `1h30m`), a 5-field cron, or an `@`-macro. Seconds and days are not interval units - `30s` and `2d` are rejected. Resolved interval must be 1 minute to 31 days.
- `lookBackSeconds`: integer, at least the `frequencyCron` interval and at most 31 days.
- `query` or `cells`, never both. For multi-cell, exactly one cell has `trigger: true`. New detections additionally need cell names limited to letters, digits, spaces, `_` and `-`; existing ones may carry other characters.
- Alert-volume controls are two separate mechanisms: `deduplicationFields` / `deduplicationWindowSeconds` (across runs, max window 24h) and `groupingField` / `groupingThreshold` (within one run, threshold 2-100). The threshold applies with or without a grouping field.
- `actorFields` / `targetFields`: at most 5 normalized field names each, priority-ordered.
- Data source selectors look like `@CloudTrail` (display name with spaces replaced by hyphens). Lookups: `@lookup_tables:<refName>/<title>`.

## What the PR-time lint catches

`pr_validate.py` runs schema validation only on every PR. It rejects:
- Missing/empty required fields
- Invalid `id` regex or `severity`/`state` enum values
- `name` length out of `[1, 200]`
- A `frequencyCron` shape or interval the scheduler will not accept
- `lookBackSeconds` below the schedule interval or above 31 days
- Out-of-range `deduplicationWindowSeconds`, `groupingThreshold`, or over-long `actorFields` / `targetFields`
- Malformed `mitreTechniques` IDs
- The removed `groupingFields` / `groupingDurationSeconds` keys
- Multi-cell with zero or multiple trigger cells, or an empty/duplicated cell name

It warns without failing on rules the API only applies to new detections, currently cell names outside `[A-Za-z0-9 _-]`. The check has no tenant access and cannot tell a create from an update.

KQL is validated server-side at sync time by the `createDetections` /
`updateDetections` mutation. Invalid KQL surfaces in the post-merge sync
run's step summary, with the API error quoted verbatim. The PR-time
check is intentionally fast and requires no tenant secret, so pull
requests opened from forks validate under the same rules.

## Authoring rules of thumb

- `logicDescription`: 2-4 sentences documenting the query's match conditions in mechanical terms. Identify the data source, the event types selected, and the fields under evaluation. Restrict the content to what the query does.
- `attackScenario`: 2-4 sentences written from the adversary's perspective. State the attacker's objective and explain how the matched events advance it. Restrict the content to threat-model reasoning.
- The two fields are intentionally distinct: `logicDescription` answers "what does the rule match?", `attackScenario` answers "why does the match indicate malicious activity?". Conflating the two weakens both.
- `mitreTechniques`: list the most specific applicable subtechnique only. Including both `T1078` and `T1078.004` is redundant.
- Avoid em-dashes; the customer-facing tone is plain.
- Do not add `mitreTactics`, `dataSourcesIds`, or `tags` to the YAML; these are derived server-side or managed through the UI.
- For exclusions, append `where ... !=` clauses inline. Multi-cell is supported but should be reserved for genuine correlations.

## Behavioural notes

- `id` is reserved permanently in the tenant after first sync. Deleting the YAML removes the detection but does not free the id.
- Every sync to an existing detection is recorded as a new version in the Vega UI's version-history pane.
- Reverting a "create" PR through `git revert` removes the detection from the tenant. Reverting a "delete" PR fails: the id is already reserved.
- The reconciler issues API calls in batches of up to 100 detections and maps the API's per-detection results back to each YAML, so the run summary names the rule that failed. Each batch is a single transaction, though: one invalid detection rolls back every other detection in the same chunk, which the summary reports as `rolled back: ...`. Whole-batch transport failures (API unreachable) are tagged with a `batch API error:` prefix instead.
- `groupingField` and `groupingThreshold` cannot be cleared through the API - an omitted value and an explicit null are indistinguishable to it. Removing the keys from a YAML leaves the tenant values in place; the reconciler stops tracking them rather than looping on a diff it cannot resolve.
- No-op updates are skipped: the reconciler diffs each YAML against the current Vega state and silently drops detections already in the target shape. This avoids resetting dynamic schedules on unchanged rules and keeps the run-summary signal-to-noise ratio high.

## Local dry-run before opening a PR

```
export VEGA_ACCESS_KEY="..."                  # or pass --access-key
python -m scripts.sync \
  --tenant-url https://app.vega.io \
  --detections-dir ./detections \
  --dry-run
```

`--dry-run` prints the plan (creates / updates / deletes / no-op skipped) without modifying tenant state. Add `--no-deletes` to also skip deletions while iterating on the schema.

## Constraints

- Do not commit changes without running the validate workflow locally or allowing CI to run on the pull request.
- Do not bypass branch protection on `main`, even with administrator rights.
- Do not commit secrets into the repository. `VEGA_ACCESS_KEY` is stored in GitHub repo Secrets.
