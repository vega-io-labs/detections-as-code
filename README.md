# Vega Detections (Detection-as-Code)

Manage tenant-custom detections as YAML in a GitHub repository, synced to your Vega tenant.

Detection-as-Code (DaC) moves the authoring surface for tenant-custom detections out of the Vega UI and into a GitHub repository.

## Capabilities

- **PR validation.** Every pull request runs schema lint against the changed YAMLs (required fields, severity values, state values, regex on `id`, multi-cell constraints). Schema failures block the check before merge.
- **Reconciling sync on merge.** On merge to `main`, the sync engine diffs every YAML against the current tenant state and submits only the deltas. Unmodified detections are skipped so dynamic schedules are not reset.
- **Per-detection result reporting.** The reconciler batches API calls in chunks of up to 100 detections and maps each per-detection result back to its YAML. A failure on one detection does not block the rest in the same batch.
- **Auditable run summary.** Every sync writes a pass/fail table to the GitHub Actions step summary, with API errors quoted verbatim. Whole-batch failures (API unreachable, tenant outage) are tagged with a `batch API error:` prefix so they read as infrastructure issues rather than detection-level failures.
- **Two sync workflows.** An automatic sync runs on push to `main`. A manual `Sync ALL detections` workflow supports bulk deployment for initial onboarding or recovery from drift.

## Prerequisites

Before adopting Detection-as-Code, ensure the following are in place:

- **GitHub Actions.** The validate and sync workflows shipped under `.github/workflows/` run on GitHub Actions. If your organization standardizes on a different CI/CD platform (GitLab CI, CircleCI, Jenkins, Buildkite, Azure Pipelines, etc.), you will need to port the workflow logic to your tool of choice. The Python sync engine in `scripts/` is platform-agnostic and remains usable as-is.
- **A Vega access key with Administrator role.** Generate it in the Vega UI under **Settings → Access Keys → Create access key**. Save the value when shown — it is displayed only once. Fine-grained permissions are not yet supported.

## First-time setup

1. **Fork the repository.** Fork https://github.com/vega-io-labs/detections-as-code into your organization on GitHub. A local `git clone` on its own is not sufficient — the workflows must run in *your* repository against *your* secrets.

2. Add your Vega access key as a repository secret:
   - GitHub: repo Settings → Secrets and variables → Actions
   - New repository secret: `VEGA_ACCESS_KEY`, paste the key

3. (Optional) Protect the `main` branch:
   - GitHub: Settings → Branches → Add rule for `main`
   - Require status check: `Validate Detection PR`
   - Require pull requests before merging

The workflows target `https://app.vega.io` and are ready to use once the access key is set. No additional tenant configuration is required.

> **Note on the seeded example.** The template includes one example detection (`detections/mimikatz-credential-theft-crowdstrike.yaml`) to illustrate the schema. It targets the `@CrowdStrike-Events` data source. If that connector is not configured in your tenant, either remove the file before your first merge or adapt it to a connector that is.

## Development workflow

For a typical change:

1. Create a branch off `main`. Add, edit, or remove a YAML under `detections/`.
2. (Recommended) Run a local dry-run against your tenant - see [Local dry-run](#local-dry-run) below.
3. Open a pull request. The `Validate Detection PR` check runs schema lint against the changed YAMLs.
4. Review and merge.
5. The `Sync Detections to Vega` workflow runs on `main`. Review its **Summary** tab for the per-detection result table.
6. Open Vega UI -> Detections to confirm the change. Each sync to an existing detection is recorded as a row in the version-history pane.

## Detection YAML layout

All YAMLs are loaded recursively from `detections/`. The subdirectory structure is at your discretion; the sync engine reads `detections/**/*.yaml` and `detections/**/*.yml` regardless of how the tree is organised. A common arrangement:

```
detections/
  identity/
    okta-impossible-travel.yaml
    okta-mfa-bypass.yaml
  cloud/
    aws/
      root-console-login.yaml
      iam-policy-too-permissive.yaml
    gcp/
  endpoint/
    crowdstrike-mimikatz.yaml
```

One detection per file. The filename is for human readability; the `id` field inside binds the YAML to the detection in Vega.

## YAML schema

> **Copy this** to start a new detection: [`docs/detection.template.yaml`](docs/detection.template.yaml). For the full field-by-field reference (types, allowed values, array conventions, examples), see [`docs/fields.md`](docs/fields.md).

### Required fields

| Field | Type | Constraints |
|---|---|---|
| `id` | string | UUID v7. Regex `^[a-z0-9][a-z0-9._-]{0,127}$`. **Permanent once synced** (see below). |
| `name` | string | 1-200 characters. |
| `severity` | int (1-4) or enum string | `1=LOW, 2=MEDIUM, 3=HIGH, 4=CRITICAL`. |
| `state` | string | `enabled`, `disabled`, or `test_mode`. |
| `frequencyCron` | string | Non-empty. Schedule on which the detection runs (e.g. `"5m"`, `"1h"`). |
| `lookBackSeconds` | int (>0) | Query lookback window, in seconds. |
| `query` **OR** `cells` | string / list | KQL. Use `query` for the single-cell case; use `cells` for multi-step correlations. Exactly one of the two must be present. See [`docs/fields.md`](docs/fields.md#query-or-cells--required-exactly-one-of-them) and the four annotated patterns in [`docs/`](#example-catalogue). |

Operational fields (`state`, `frequencyCron`, `lookBackSeconds`) are required by design: silent defaults on security infrastructure introduce risk. Each value must be specified explicitly.

### Optional fields (with defaults)

| Field | Type | Default | Notes |
|---|---|---|---|
| `logicDescription` | string | `""` | Human-readable description of what the detection looks for. Shown to analysts during triage. |
| `attackScenario` | string | `""` | Human-readable description of the adversary behaviour. |
| `mitreTechniques` | list[string] | `[]` | MITRE technique IDs, e.g. `["T1078", "T1078.004"]`. Tactics are derived server-side. |
| `references` | list[string] | `[]` | URLs related to the detection. |
| `groupingFields` | list[string] | `[]` | OCSF dotted paths used to group hits into a single alert. |
| `groupingDurationSeconds` | int | `null` | Grouping window in seconds. |

### YAML list conventions

Empty list, inline list, and block list are all valid:

```yaml
references: []                                  # empty

mitreTechniques: ["T1078", "T1078.004"]         # inline

groupingFields:                                  # block
  - actor.user.name
  - src_endpoint.ip
```

### Full example

```yaml
id: "019e206b-17cd-759a-b26e-e34a55944ea1"     # UUID v7 - generate your own; do not reuse this one
name: "Root Account Console Login"
severity: 4                                     # CRITICAL
state: "enabled"
frequencyCron: "5m"
lookBackSeconds: 300
mitreTechniques: ["T1078.004"]
logicDescription: "Matches AWS CloudTrail ConsoleLogin events where the actor is the account root user."
attackScenario: "An adversary with stolen AWS root credentials logs in to the console to perform privileged actions outside normal scoped-IAM access patterns. Root logins are exceedingly rare in healthy environments because day-to-day IAM should use scoped roles, so any root login warrants investigation."
references:
  - "https://docs.aws.amazon.com/IAM/latest/UserGuide/root-user-best-practices.html"
  - "https://attack.mitre.org/techniques/T1078/004/"
groupingFields:
  - "actor.user.name"
groupingDurationSeconds: 900
query: |-
  @CloudTrail
  | where event_name =~ "ConsoleLogin"
  | where actor.user.type =~ "Root"
```

### Generating an `id`

Generate a UUID version 7. UUID v7 is time-ordered, lowercase, and matches the Vega `externalId` regex.

```bash
uuidgen -7                                              # macOS 14+ / util-linux 2.39+
python -c "import uuid; print(uuid.uuid7())"            # Python 3.14+
python -c "import secrets,time; ms=int(time.time()*1000); r=secrets.randbits(74); print(f'{ms:012x}-{(0x7<<12)|(r>>62):04x}-{(0x8000)|((r>>48)&0x3fff):04x}-{r&0xffffffffffff:012x}'.replace('-','',1)[:36])"  # any Python
```

One id per detection; never reuse one across files.

### `id` is permanent

Once a YAML with a given `id` is synced to your tenant, that `id` is reserved permanently. Deleting the YAML removes the detection, but the `id` itself cannot be reused. To rebuild equivalent logic, generate a new UUID.

To retire a detection while keeping its id reserved, set `state: "disabled"` rather than deleting the YAML.

## Writing the `query`

Single-cell Vega KQL pipeline, starting with a data source selector.

### Referencing a data source

```kql
@CloudTrail | where event_name =~ "ConsoleLogin"
@Okta-System-Logs | where eventType == "user.session.start"
@Windows-OS-Logs | where event_id == 4625
```

Use the data source display name with spaces replaced by hyphens. The full list of connectors and their selectors is in the Vega UI under Data Sources. **Only data sources with a configured connector in your tenant are queryable.** The sync workflow's `createDetections` call rejects detections that reference data sources that are not connected, surfacing `table selectors not found: @X` in the run's step summary.

### Referencing a lookup table

```kql
@CloudTrail
| project src_endpoint.ip
| join kind=inner (
    @lookup_tables:my-allowlist/Allowed-IPs
    | project ip_address
  ) on $left.src_endpoint.ip == $right.ip_address
```

The form is `@lookup_tables:<refName>/<title>`. Lookup tables are created and managed in the Vega UI; this template does not manage lookups.

### Multi-cell detections

Use `cells:` in place of `query:`, with one cell marked `trigger: true`. The trigger cell composes the others by name (`@CellA`). Comma-separated references express a union; `| join (@cell)` expresses a correlation; cells can also pipe into one another (`@A | where ...`) for chained composition.

`detectionCells:` is accepted as a synonym for `cells:` for compatibility with YAMLs exported from Vega's internal detection libraries.

See the [example catalogue](#example-catalogue) below for the four multi-cell patterns.

## Example catalogue

Four annotated patterns are provided under `docs/`. Copy the file that most closely matches the intended detection, replace `id` with a fresh UUID v7, rename, and adapt.

| # | File | When to use |
|---|---|---|
| 1 | [`docs/example-single-cell.yaml`](docs/example-single-cell.yaml) | One KQL pipeline, no correlation across queries. |
| 2 | [`docs/example-multi-cell-exclusion.yaml`](docs/example-multi-cell-exclusion.yaml) | State cell + trigger that references it via `@cells:<refId>/<title>` and applies an inline `where not (...)` exclusion. |
| 3 | [`docs/example-multi-cell-or.yaml`](docs/example-multi-cell-or.yaml) | N state cells composed by the trigger via comma-separated `@Cell` refs. Fires when ANY state cell matches. |
| 4 | [`docs/example-multi-cell-chain.yaml`](docs/example-multi-cell-chain.yaml) | Cells pipe into one another (`@A | where ...` inside cell B). The trigger transitively reaches every cell. |

For a blank placeholder template (single-cell skeleton), use [`docs/detection.template.yaml`](docs/detection.template.yaml).

## The CI/CD workflows

Three GitHub Actions workflows ship with this template:

| Workflow | File | Trigger | What it does |
|---|---|---|---|
| **Validate Detection PR** | `.github/workflows/validate.yml` | Pull request touching `detections/**` or `scripts/**` | Schema lint on each changed YAML. No tenant secret needed; runs cleanly on PRs from forks. |
| **Sync Detections to Vega** | `.github/workflows/sync.yml` | Push to `main` touching `detections/**` or `scripts/**`. Also `workflow_dispatch`. | Reconciles every YAML against the tenant, batched in chunks of 100. `dry_run` and `no_deletes` inputs available on manual dispatch. |
| **Sync ALL detections (manual)** | `.github/workflows/sync-all.yml` | Manual (`workflow_dispatch`) only | Same reconcile, but defaults to `dry_run=true` and `no_deletes=true`. Use for first-run bulk deploy or recovery after a partial sync. |

Both sync workflows read `VEGA_ACCESS_KEY` from the repository secret. The tenant URL is `https://app.vega.io`.

## Reading the run summary

The sync workflow writes its result to the GitHub Actions **Summary** tab. The header summarises the run at a glance:

```
## ✅ Detection sync — 12 ok, 0 failed (creates=2 updates=3 deletes=0 no_op=7)
```

Below it is a per-detection table with one row per action (create / update / delete / set_state):

```
┏━━━━┳━━━━━━━━┳━━━━━━━━━━━━━━━━┳━━━━━━━━━━━━━━━━━━━━━┳━━━━━━━━━━━━━━━━━━━┓
┃ OK ┃ Action ┃ externalId     ┃ Name                ┃ Error             ┃
┡━━━━╇━━━━━━━━╇━━━━━━━━━━━━━━━━╇━━━━━━━━━━━━━━━━━━━━━╇━━━━━━━━━━━━━━━━━━━┩
│ ✓  │ create │ tor-login      │ Tor Network Login   │                   │
│ ✗  │ update │ suspicious-mfa │ Suspicious MFA Push │ severity: invalid │
└────┴────────┴────────────────┴─────────────────────┴───────────────────┘
```

- `creates` / `updates` / `deletes` count the actions actually planned.
- `no_op` counts detections whose YAML matched the current Vega state exactly - skipped to avoid resetting dynamic schedules.
- The Error column shows per-detection validation errors verbatim from the API.
- A whole-batch transport failure surfaces as up to 100 rows with the same `batch API error: ...` text; that indicates a tenant or network issue, not a detection-level failure.

## Local dry-run

Before opening a pull request, reconcile against your tenant locally to preview the change set:

```bash
pip install -r requirements.txt

export VEGA_ACCESS_KEY="..."                     # or pass --access-key

# Print the plan without applying it
python -m scripts.sync \
  --tenant-url https://app.vega.io \
  --detections-dir ./detections \
  --dry-run

# Skip deletes while iterating on the schema
python -m scripts.sync \
  --tenant-url https://app.vega.io \
  --detections-dir ./detections \
  --dry-run --no-deletes

# Merge multiple detection roots (the flag is repeatable)
python -m scripts.sync \
  --detections-dir ./detections \
  --detections-dir ./detections-overrides \
  --dry-run
```

`--dry-run` prints the plan (creates / updates / deletes / no-op skipped) and exits without modifying tenant state. `--no-deletes` permits creates, updates, and state changes but skips the delete step.

## Disable vs delete vs revert

| Goal | Action |
|---|---|
| Pause a detection while keeping its id reserved | Set `state: "disabled"` and merge. |
| Validate a tuning change against production data before promoting | Set `state: "test_mode"` and merge. The resulting alerts are isolated from incident correlation. |
| Permanently retire a detection | Delete the YAML file. The next sync removes it from the tenant. The `id` remains reserved; any rebuild requires a new UUID. |
| Roll back a change | `git revert` the offending commit. Reverting a "create" PR removes the detection from the tenant; reverting a "delete" PR fails because the `id` is already reserved - generate a new id instead. |
| Pause repository-wide syncing | Disable the `Sync Detections to Vega` workflow under repo Settings -> Actions. |

## Audit trail

This template does not push PR links or commit metadata into Vega. The git history of each YAML serves as the audit log:

```bash
git log -- detections/path/to/my-detection.yaml      # who changed what, when
git blame detections/path/to/my-detection.yaml       # line-level attribution
```

Inside Vega, each merged change appears as a row in the detection's version-history pane.

## Troubleshooting

### PR validation (before merge)

| Symptom | Likely cause | Fix |
|---|---|---|
| Validate fails with `missing required field 'X'` | YAML is missing a mandatory field. | Check the schema table above; add the field. |
| Validate fails with `'id' must match ^[a-z0-9]...` | id has uppercase, an invalid character, or starts with `-`/`.`/`_`. | Regenerate as a UUID v7 (lowercase, hex with hyphens). |
| Validate fails with `'name' must be 1-200 characters` | name is empty or too long. | Trim. |
| Validate fails with `invalid severity` / `invalid state` | severity is outside `1-4` / not in `LOW/MEDIUM/HIGH/CRITICAL`; state is not one of `enabled/disabled/test_mode`. | Use one of the listed values. |
| Validate fails with `exactly one cell must have 'trigger: true'` | Multi-cell YAML has zero or multiple trigger cells. | Mark exactly one cell `trigger: true`. |
| Validate fails with `cells[i].name ... is duplicated` or `must not start with '@'` | Cell name collision or `@`-prefixed name. | Make cell names unique within the detection and don't prefix them with `@`. |

### Sync at merge time

| Symptom | Likely cause | Fix |
|---|---|---|
| Sync fails with `table selectors not found: @X` | Your tenant does not have a connector configured for that data source. | Onboard the connector in the Vega UI before merging, or remove the detection. |
| Sync fails with `parse pipeline query language` | KQL syntax error. The line and column are shown in the workflow log. | Fix the KQL in a follow-up PR. |
| Sync fails with `external_id "..." already exists` | That id was previously used. | Generate a new UUID; old ids remain reserved permanently. |
| Sync exits non-zero but most detections succeeded | Per-detection result mapping: a subset has validation errors. | Review the workflow step summary to identify the failing detections and address each individually. |
| A chunk of detections all fail with the same `batch API error: ...` line | The API was unreachable or returned a transport error for that batch. | Re-run the workflow. Transient transport errors clear on retry; the next run is idempotent (no-op updates are skipped). |
| Sync reports failures stating the detection already exists, yet the rule is visible in the UI | The first attempt landed on Vega but the response was lost in transit; the retry encountered a duplicate. | The detection is healthy. Re-run the workflow; the next pass records it as a no-op. |

### Runtime (after sync)

| Symptom | Likely cause | Fix |
|---|---|---|
| Detection is `HEALTHY` in the UI but never fires | KQL parses and runs but does not match any events. | Iterate on the query against the same data source. |
| Detection fires too often or produces noise | Tuning gap. | Add exclusion `where ... != ...` clauses, or set `state: "test_mode"` so the rule continues to run against production data without firing incidents while you tune. |

## Further reading

Canonical Vega platform documentation:

- [KQL reference](https://docs.vega.io/query/quickguide) - language, operators, worked use cases
- [Lookup tables](https://docs.vega.io/lookup-tables/lookup_tables) - static and dynamic lookups
- [Detections](https://docs.vega.io/detections/overview) - lifecycle, test mode, health, auto-tuning

## Limitations (v1)

- **Custom detections only.** This template manages tenant-custom detections authored as YAML in this repository. Vega's built-in library detections are not in scope; manage those through the Vega UI.
- **No drift detection.** The sync workflow runs on pushes to `main` that touch `detections/**` or `scripts/**`, and on manual dispatch. Changes made to a synced detection through the Vega UI between repository syncs persist silently and are reverted to the YAML state on the next sync. There is no warning, alert, or reconciliation report for UI-side edits. Treat the repository as the single source of truth, and run the **Sync ALL detections** workflow periodically to force-reconcile if UI edits are suspected.
- Lookups and data sources must already exist in the tenant.
- A merge that fails partway through leaves the tenant in a partially-applied state. Re-running the workflow after fixing the offending YAML converges (idempotent).
- The Access Key currently requires **Administrator** role; fine-grained scoping is not yet supported.
- `deleteDetection` is a single-detection API; deletes run one rule at a time. Creates and updates batch in chunks of 100.
