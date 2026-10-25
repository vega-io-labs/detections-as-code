# Vega Detections (Detection-as-Code)

Manage tenant-custom detections, skills and memories in a GitHub repository, synced to your Vega tenant.

Detection-as-Code (DaC) moves the authoring surface for tenant-custom detections, and for the skills and memories Vega agents use when they triage and investigate, out of the Vega UI and into a GitHub repository.

## Capabilities

- **PR validation.** Every pull request runs schema lint against the changed YAMLs (required fields, severity values, state and mode values, regex on `id`, schedule and lookback bounds, multi-cell constraints). Schema failures block the check before merge.
- **Reconciling sync on merge.** On merge to `main`, the sync engine diffs every YAML against the current tenant state and submits only the deltas. Unmodified detections are skipped so dynamic schedules are not reset.
- **Per-detection result reporting.** The reconciler batches API calls in chunks of up to 100 detections and maps each per-detection result back to its YAML, so the run summary names the rule that failed. Each batch is one transaction: an invalid detection rolls back the others in the same chunk, and they are reported as blocked rather than applied. This is what the PR check exists to prevent.
- **Auditable run summary.** Every sync writes a pass/fail table to the GitHub Actions step summary, with API errors quoted verbatim. Whole-batch failures (API unreachable, tenant outage) are tagged with a `batch API error:` prefix so they read as infrastructure issues rather than detection-level failures.
- **Skills as code.** Skills under `skills/`, one `SKILL.md` each, go through the same PR check and the same reconciling sync. Detections in the repository can attach them by the `id` in the file. Skills made in the UI and Vega library skills are never touched. See [Skills](#skills).
- **Memories as code.** Memories under `memories/` go through the same PR check and the same reconciling sync. The sync only manages the memories it created, marked with a `detections-as-code` label, so memories written in the UI or learned by Vega are never touched. See [Memories](#memories).
- **Two sync workflows.** An automatic sync runs on push to `main`. A manual `Sync ALL detections, skills and memories` workflow supports bulk deployment for initial onboarding or recovery from drift.

## Prerequisites

Before adopting Detection-as-Code, ensure the following are in place:

- **GitHub Actions.** The validate and sync workflows shipped under `.github/workflows/` run on GitHub Actions. If your organization standardizes on a different CI/CD platform (GitLab CI, CircleCI, Jenkins, Buildkite, Azure Pipelines, etc.), you will need to port the workflow logic to your tool of choice. The Python sync engine in `scripts/` is platform-agnostic and remains usable as-is.
- **Agent and label permissions on the access key** (only if you sync skills or memories). Skills need `AgentsWrite`. Memories need `AgentsRead` and `AgentsWrite`, plus `LabelsRead` and `LabelsWrite`: the sync reads the tenant's labels to resolve each file's `labels`, and creates the `detections-as-code` label on first use.
- **Memories enabled for your organization** (only if you sync memories). Without them, the sync skips an empty `memories/` folder and reports an error when the folder holds memories.
- **A Vega access key with Administrator role.** Generate it in the Vega UI under **Settings → Access Keys → Create access key**. Save the value when shown — it is displayed only once. Fine-grained permissions are not yet supported.

## First-time setup

1. **Fork the repository.** Fork https://github.com/vega-io-labs/detections-as-code into your organization on GitHub. A local `git clone` on its own is not sufficient — the workflows must run in *your* repository against *your* secrets.

2. Add your Vega access key as a repository secret:
   - GitHub: repo Settings → Secrets and variables → Actions
   - New repository secret: `VEGA_ACCESS_KEY`, paste the key
   - Second repository secret: `VEGA_ACCESS_KEY_ID`, paste the key's ID (shown next to the key in the Vega UI). Every API call must carry the ID of the key it authenticates with, so any key created on or after 2026-06-18 needs this secret - in practice, any key you create today. Only keys predating that date are grandfathered and work without it.

3. (Optional) Protect the `main` branch:
   - GitHub: Settings → Branches → Add rule for `main`
   - Require status check: `validate` (the job in the `Validate PR` workflow)
   - Require pull requests before merging

The workflows target `https://app.vega.io` and are ready to use once the access key is set. No additional tenant configuration is required.

> **Note on the seeded example.** The template includes one example detection (`detections/mimikatz-credential-theft-crowdstrike.yaml`) to illustrate the schema. It targets the `@CrowdStrike-Events` data source. If that connector is not configured in your tenant, either remove the file before your first merge or adapt it to a connector that is.

## Development workflow

For a typical change:

1. Create a branch off `main`. Add, edit, or remove a YAML under `detections/` or `memories/`, or a `SKILL.md` under `skills/`.
2. (Recommended) Run a local dry-run against your tenant - see [Local dry-run](#local-dry-run) below.
3. Open a pull request. The `Validate PR` check runs schema lint against the changed files.
4. Review and merge.
5. The `Sync Detections, Skills and Memories to Vega` workflow runs on `main`. Review its **Summary** tab for the per-detection, per-skill and per-memory result table.
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
| `frequencyCron` | string | Schedule on which the detection runs: an hour/minute interval (`"5m"`, `"1h"`, `"1h30m"`), a 5-field cron, or an `@`-macro. Resolved interval must be 1 minute to 31 days. |
| `lookBackSeconds` | int | Query lookback window, in seconds. Must be **>= the `frequencyCron` interval** (a shorter one would skip data between runs) and <= 31 days. |
| `query` **OR** `cells` | string / list | KQL. Use `query` for the single-cell case; use `cells` for multi-step correlations. Exactly one of the two must be present. See [`docs/fields.md`](docs/fields.md#query-or-cells--required-exactly-one-of-them) and the four annotated patterns in [`docs/`](#example-catalogue). |

Operational fields (`state`, `frequencyCron`, `lookBackSeconds`) are required by design: silent defaults on security infrastructure introduce risk. Each value must be specified explicitly.

### Optional fields (with defaults)

| Field | Type | Default | Notes |
|---|---|---|---|
| `mode` | string | `alert` | How the detection's alerts take part in triage: `alert` (AI triage, correlation, can open an incident), `evidence` (skips triage, escalates only through correlation) or `monitor` (recorded only). |
| `logicDescription` | string | `""` | Human-readable description of what the detection looks for. Shown to analysts during triage. |
| `attackScenario` | string | `""` | Human-readable description of the adversary behaviour. |
| `mitreTechniques` | list[string] | `[]` | MITRE technique IDs, e.g. `["T1078", "T1078.004"]`. Tactics are derived server-side. |
| `references` | list[string] | `[]` | URLs related to the detection. |
| `deduplicationFields` | list[string] | `[]` | OCSF dotted paths used to suppress duplicate alerts: new events matching an active alert on every listed field update that alert instead of opening a new one. |
| `deduplicationWindowSeconds` | int | `0` | Deduplication window in seconds, max `86400`. `0` disables deduplication. |
| `groupingField` | string | `null` | Burst protection: when one run returns more than `groupingThreshold` rows, results are grouped into one alert per distinct value of this normalized field. Default `null` collapses such a run into a single alert. |
| `groupingThreshold` | int | `10` | Row count in one run that activates burst protection. Range 2-100. Applies with or without `groupingField`. |
| `actorFields` | list[string] | `[]` | Priority-ordered normalized field names used to extract the alert's Actor, max 5. Empty uses Vega's per-data-type defaults. |
| `targetFields` | list[string] | `[]` | Priority-ordered normalized field names used to extract the alert's Target, max 5. Empty uses Vega's per-data-type defaults. |
| `skillIds` | list[string] | `[]` | IDs of `TRIAGE` or `INVESTIGATION` skills Vega loads when triaging this detection's alerts, max 20. For a skill under `skills/`, use the `id` in its `SKILL.md`. The list is authoritative: an empty list detaches skills added in the UI. Must stay empty for `evidence` and `monitor` detections. |

`groupingFields` and `groupingDurationSeconds` were removed from the detection API and are rejected by the sync rather than remapped. `groupingDurationSeconds` becomes `deduplicationWindowSeconds`; `groupingFields` has no single successor and resolves to either `deduplicationFields` or `groupingField` depending on what you meant. See [`docs/fields.md`](docs/fields.md#two-ways-to-reduce-alert-volume).

### YAML list conventions

Empty list, inline list, and block list are all valid:

```yaml
references: []                                  # empty

mitreTechniques: ["T1078", "T1078.004"]         # inline

deduplicationFields:                             # block
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
deduplicationFields:
  - "actor.user.name"
deduplicationWindowSeconds: 900
query: |-
  @CloudTrail
  | where event_name =~ "ConsoleLogin"
  | where actor.user.type =~ "Root"
```

### Generating an `id`

Generate a UUID version 7. UUID v7 is time-ordered, lowercase, and matches the Vega `externalId` regex.

```bash
# Python 3.14+
python3 -c "import uuid; print(uuid.uuid7())"

# any Python 3
python3 -c "import os,time,uuid; b=bytearray(os.urandom(16)); b[0:6]=int(time.time()*1000).to_bytes(6,'big'); b[6]=(b[6]&0x0f)|0x70; b[8]=(b[8]&0x3f)|0x80; print(uuid.UUID(bytes=bytes(b)))"

# util-linux 2.39+ (Linux). Not macOS: its uuidgen has no -7 and emits uppercase v4
uuidgen -7
```

> **macOS `uuidgen` does not work here.** It takes no `-7` flag, and plain `uuidgen`
> returns an uppercase version 4 UUID such as `E87603A6-CAB0-42CF-AD76-A528EB04132F`.
> That is rejected: the id regex is lowercase-only. Use one of the Python commands
> above, or lowercase the output with `uuidgen | tr 'A-Z' 'a-z'` — though that still
> gives you a v4, not the time-ordered v7 this template recommends.

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

## Skills

A skill is a set of instructions Vega agents follow for one kind of work: how to triage a class of alert, how to investigate an incident, how to tune or hunt. Skills live under `skills/`, one folder per skill holding a `SKILL.md`, in any layout:

```
skills/
  triage/
    service-account-sign-in/
      SKILL.md
```

> **Copy this** to start a new skill: [`docs/skill.template.md`](docs/skill.template.md). For a worked example see [`docs/example-skill.md`](docs/example-skill.md), and for the full field reference [`docs/skills.md`](docs/skills.md).

```markdown
---
id: "8b0f5a3e-2c4d-4e6f-9a1b-3c5d7e9f1a2b"   # a UUID you generate once
name: "Service Account Sign-In Triage"
description: "Sign-ins by service accounts from outside their fixed egress range. Use when ..."
type: "triage"     # triage | investigation | tuning | hunting | exploration | detection_generation | memory
---

# Triage steps

The instructions, in Markdown, at most 500 lines.
```

| Field | Required | Notes |
|---|---|---|
| `id` | yes | A UUID, generated once (`python3 -c 'import uuid; print(uuid.uuid4())'`). Links the file to its skill in Vega. |
| `name` | yes | 1-255 characters. A new file named like a skill already in the tenant is blocked, since `createSkills` matches by name and would take that skill over. |
| `description` | yes | 1-5000 characters. The agent picks skills by name and description, so say when to use it. |
| `type` | yes | The workflow that loads the skill. Only `triage` and `investigation` skills can be attached to a detection. |
| body | yes | The instructions: everything after the closing `---`. |

How the sync treats skills:

- **It manages every tenant skill that has an `id` (externalId)**, the same rule as detections. Skills made in the Vega UI have none and Vega library skills are read-only, so neither is ever changed or deleted. A skill another tool created through the API with an `externalId` is deleted unless it has a `SKILL.md` here, so keep one repository per tenant. A new file named like a skill made in the UI is blocked instead of overwriting it.
- **The `id` is the identity.** Name, description, type and instructions can all change and the skill is updated in place, with its detections still attached.
- **Detections can use it right away.** Put the skill's `id` in a detection's `skillIds`; the sync swaps in the id Vega assigned. Skills sync before detections, so both can land in one pull request.
- **Labels stay in the UI.** The sync never sends labels, so the labels you set in Vega are kept.
- **Deleting the folder deletes the skill** on the next sync (unless `--no-deletes`). Remove its id from detections' `skillIds` in the same pull request; the PR check fails until you do.
- **A missing `skills/` folder turns skill sync off.** The template does not ship one: create it (`mkdir skills`) with your first skill. An empty folder means "manage zero skills" and deletes any managed skill, so run **Sync ALL** as a dry run before the first merge that adds `skills/`.
- **Use a fresh UUID for every new skill.** A reused id gets the same tenant id back, so detections that used the old skill would pick it up again until the next sync detaches it.

## Memories

A memory is a note about your environment that Vega agents read when they triage alerts and investigate incidents: known benign activity, the owner of an asset, an accepted risk, a standing instruction. Memories live under `memories/`, one per file, in any subfolder layout:

```
memories/
  scanners/
    vulnerability-scanner.yaml
  assets/
    payroll-server-owner.yaml
  accepted-risks/
    legacy-ftp-partner.yaml
```

> **Copy this** to start a new memory: [`docs/memory.template.yaml`](docs/memory.template.yaml). For a worked example see [`docs/example-memory.yaml`](docs/example-memory.yaml), and for the full field reference [`docs/memories.md`](docs/memories.md).

```yaml
title: "Approved vulnerability scanner scanner-01"
description: "Weekly authenticated vulnerability scans from scanner-01 (192.0.2.10) are expected and approved."
content: |-
  scanner-01 runs authenticated scans every Sunday 02:00-06:00 UTC.

  Not covered, escalate instead:
  - Any activity from 192.0.2.10 outside the Sunday window.
status: "enabled"                    # enabled | disabled
expiresAt: "2027-01-31"              # optional
entities:                            # optional: account | device | ip | domain
  - type: ip
    value: "192.0.2.10"
labels: []                           # optional: names of labels that exist in your tenant
```

| Field | Required | Notes |
|---|---|---|
| `title` | yes | 1-150 characters, unique across `memories/`. Links the file to its memory in Vega. |
| `description` | yes | 1-300 characters, one line. Agents read it to decide if the memory applies. |
| `content` | yes | 1-5000 characters. |
| `status` | no | `enabled` (default) or `disabled`. |
| `expiresAt` | no | ISO 8601. Agents stop using the memory after it. |
| `entities` | no | At most 50 `{type, value}` pairs. |
| `labels` | no | Label names; they must exist in the tenant. |

How the sync treats memories:

- **It only manages its own memories.** Every memory the sync creates carries the `detections-as-code` label, created on first use. Only labelled memories are updated and deleted, so memories written in the Vega UI and memories Vega learns from analyst verdicts are left alone. A file whose title matches one of those is blocked rather than created a second time.
- **The title is the identity.** There is no `id` field: a file is matched to the labelled memory with the same title. Changing a title therefore deletes the old memory and creates a new one, with a new `MEM-` id and an empty usage history.
- **The file is the source of truth.** Every changed field is written, and `entities` and `labels` replace what is attached in the UI. Removing `expiresAt` removes the expiration.
- **Deleting the file deletes the memory** on the next sync (unless `--no-deletes`). Set `status: "disabled"` to keep it but stop agents from using it.
- **A missing `memories/` folder turns memory sync off.** Delete the folder if you do not want to manage memories from this repository; an empty folder means "manage zero memories" and removes any memory the sync created earlier.
- **Each memory is its own API call.** There is no batch call for memories, so one failing memory never blocks another. The sync runs deletes first, then updates, then creates, so freeing room under the tenant's limit of 250 active memories happens before new ones are added.

## The CI/CD workflows

Three GitHub Actions workflows ship with this template:

| Workflow | File | Trigger | What it does |
|---|---|---|---|
| **Validate PR** | `.github/workflows/validate.yml` | Pull request touching `detections/**`, `skills/**`, `memories/**` or `scripts/**` | Schema lint on each changed YAML and `SKILL.md`. No tenant secret needed; runs cleanly on PRs from forks. |
| **Sync Detections, Skills and Memories to Vega** | `.github/workflows/sync.yml` | Push to `main` touching `detections/**`, `skills/**`, `memories/**` or `scripts/**`. Also `workflow_dispatch`. | Reconciles everything against the tenant: skills first, then detections batched in chunks of 100, then memories one call each. `dry_run` and `no_deletes` inputs available on manual dispatch. |
| **Sync ALL detections, skills and memories (manual)** | `.github/workflows/sync-all.yml` | Manual (`workflow_dispatch`) only | Same reconcile, but defaults to `dry_run=true` and `no_deletes=true`. Use for first-run bulk deploy or recovery after a partial sync. |

Both sync workflows read `VEGA_ACCESS_KEY` and `VEGA_ACCESS_KEY_ID` from the repository secrets. On scope-enabled (ABAC) tenants where the key is bound to multiple scopes, set the `VEGA_SCOPE_ID` repository variable. The tenant URL is `https://app.vega.io`.

## Reading the run summary

The sync workflow writes its result to the GitHub Actions **Summary** tab. The header summarises the run at a glance:

```
## ✅ Vega sync — 13 ok, 0 failed (creates=2 updates=3 deletes=0 no_op=7)

Skills: creates=1 updates=0 deletes=0 blocked=0 no_op=3

Memories: creates=1 updates=0 deletes=0 blocked=0 no_op=4
```

Below it is one table with a row per action (create / update / delete / set_state). The Id column holds the detection's `externalId`, the skill's `id` or the memory's `MEM-` id:

```
┏━━━━┳━━━━━━━━━━━┳━━━━━━━━┳━━━━━━━━━━━━━━━━┳━━━━━━━━━━━━━━━━━━━━━━━━━━━━┳━━━━━━━━━━━━━━━━━━━┓
┃ OK ┃ Object    ┃ Action ┃ Id             ┃ Name                       ┃ Error             ┃
┡━━━━╇━━━━━━━━━━━╇━━━━━━━━╇━━━━━━━━━━━━━━━━╇━━━━━━━━━━━━━━━━━━━━━━━━━━━━╇━━━━━━━━━━━━━━━━━━━┩
│ ✓  │ detection │ create │ tor-login      │ Tor Network Login          │                   │
│ ✗  │ detection │ update │ suspicious-mfa │ Suspicious MFA Push        │ severity: invalid │
│ ✓  │ memory    │ create │ MEM-K7QX2      │ Approved vulnerability ... │                   │
└────┴───────────┴────────┴────────────────┴────────────────────────────┴───────────────────┘
```

- `creates` / `updates` / `deletes` count the actions actually planned.
- `no_op` counts detections whose YAML matched the current Vega state exactly - skipped to avoid resetting dynamic schedules.
- The Error column shows per-detection validation errors verbatim from the API.
- A whole-batch transport failure surfaces as up to 100 rows with the same `batch API error: ...` text; that indicates a tenant or network issue, not a detection-level failure.
- A `rolled back: ...` error means that detection was valid but was not written, because another detection in the same 100-item chunk failed validation and the API applies each chunk as one transaction. Fix the named offender and re-run; nothing partial was left behind.

## Local dry-run

Before opening a pull request, reconcile against your tenant locally to preview the change set:

```bash
pip install -r requirements.txt

export VEGA_ACCESS_KEY="..."                     # or pass --access-key
export VEGA_ACCESS_KEY_ID="..."                  # or pass --access-key-id; the key's own id, required for keys created on or after 2026-06-18

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

Skills are read from `./skills` and memories from `./memories` by default; pass `--skills-dir` or `--memories-dir` (both repeatable) to point elsewhere. When none of the given folders exists, that kind is skipped.

`--dry-run` prints the plan (creates / updates / deletes / no-op skipped, plus the skill and memory plans) and exits without modifying tenant state. It exits non-zero when anything is blocked, since the real sync would report those as failures. `--no-deletes` permits creates, updates, and state changes but skips the delete step.

## Disable vs delete vs revert

| Goal | Action |
|---|---|
| Pause a detection while keeping its id reserved | Set `state: "disabled"` and merge. |
| Validate a tuning change against production data before promoting | Set `state: "test_mode"` and merge. The resulting alerts are isolated from incident correlation. |
| Permanently retire a detection | Delete the YAML file. The next sync removes it from the tenant. The `id` remains reserved; any rebuild requires a new UUID. |
| Roll back a change | `git revert` the offending commit. Reverting a "create" PR removes the detection from the tenant; reverting a "delete" PR fails because the `id` is already reserved - generate a new id instead. |
| Stop agents from using a memory but keep it | Set `status: "disabled"` on the memory and merge. |
| Remove a memory | Delete its file. Unlike a detection id, a memory title can be reused right away. |
| Pause repository-wide syncing | Disable the `Sync Detections, Skills and Memories to Vega` workflow under repo Settings -> Actions. |

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
| Validate fails with `invalid mode` | mode is not one of `alert/evidence/monitor`. | Use one of the listed values, or drop the key to get `alert`. |
| Validate fails with `exactly one cell must have 'trigger: true'` | Multi-cell YAML has zero or multiple trigger cells. | Mark exactly one cell `trigger: true`. |
| Validate fails with `cells[i].name ... is duplicated` | Two cells in one detection share a name. | Make cell names unique within the detection. |
| Validate warns `cells[i].name ... contains characters the API rejects when creating a detection` | Punctuation such as `.` in a cell name. | Harmless for a detection that already exists; rename before merging if it is new, or the create fails and rolls back its batch. |
| Validate fails with `'groupingFields' is no longer accepted by the detection API` | The YAML predates the removal of the plural grouping fields. | Choose by intent - `deduplicationFields` to fold repeat alerts together across runs, `groupingField` to split one noisy run. `groupingDurationSeconds` becomes `deduplicationWindowSeconds`. The old keys never took effect, so review the value before carrying it over. |
| Validate fails with `unknown field 'category'` (or `tags`, `version`, `author`) on a skill | The file was copied from a Vega library skill, which carries keys this repository does not sync. | Rename `category` to `type`; remove the others. Labels are set in the Vega UI. |
| Validate fails with `'id' must be a UUID` on a skill | The skill's `id` is missing or not a UUID. | Generate one with `python3 -c 'import uuid; print(uuid.uuid4())'`. |
| Validate fails with `duplicate id` or `duplicate name` on a skill | Two `SKILL.md` files share an id (often a copied file) or a name. | Give the copy a new id and a distinct name. |
| Validate fails with `name the file SKILL.md exactly` | A skill file is named `skill.md` or similar. | Rename it to `SKILL.md`; the sync reads no other name. |
| Validate fails with `'skillIds' names skill ..., whose ... this PR deletes` | The PR deletes a `SKILL.md` that a detection still uses. | Remove the id from that detection's `skillIds` in the same PR. |
| Validate fails with `only triage and investigation skills can be attached` | A detection's `skillIds` names a repository skill of another type. | Attach a triage or investigation skill, or change the skill's `type`. |
| Validate fails with `duplicate title` on a memory | Two files under `memories/` share a title, which is the memory's identity. | Make the titles unique. |
| Validate fails with `unknown field 'enabled'` (or `name`, `id`) on a memory | The memory schema uses `status`, `title`, and has no id. | Rename the key as the message says. |
| Validate warns `'expiresAt' ... is in the past` | The memory has expired. | Delete the file, or move the date forward. A new memory with a past date fails the sync. |
| Validate fails with `'lookBackSeconds' must be >= the Ns 'frequencyCron' interval` | The lookback window is shorter than the schedule, which would skip data between runs. | Raise `lookBackSeconds` to at least the interval, or shorten `frequencyCron`. |

### Sync at merge time

| Symptom | Likely cause | Fix |
|---|---|---|
| Sync fails with `table selectors not found: @X` | Your tenant does not have a connector configured for that data source. | Onboard the connector in the Vega UI before merging, or remove the detection. |
| Sync fails with `parse pipeline query language` | KQL syntax error. The line and column are shown in the workflow log. | Fix the KQL in a follow-up PR. |
| Sync fails with `external_id "..." already exists` | That id was previously used. | Generate a new UUID; old ids remain reserved permanently. |
| Sync exits non-zero and a chunk reports `rolled back: ...` | One detection in that chunk failed validation, and the chunk is applied as a single transaction. | Fix the detections whose rows carry a real API error; the rolled-back ones need no change and land on the next run. |
| Sync fails with `login_machine failed: 500 ... INTERNAL_SERVER_ERROR` | The access key is inactive - deactivated or past its expiry date. | Create a new access key in the Vega UI and update the `VEGA_ACCESS_KEY` and `VEGA_ACCESS_KEY_ID` secrets. |
| Authentication succeeds, then every API call fails with HTTP 400 `X-Vega-Key-Id header is required` | The key was created on or after 2026-06-18 and `VEGA_ACCESS_KEY_ID` is unset or holds the wrong id. The key exchange itself is unauthenticated, which is why it gets that far. | Set the `VEGA_ACCESS_KEY_ID` repository secret to that key's own id, as shown next to it in the Vega UI. |
| Login succeeds but every query fails with 403 `NO_SCOPE_FOR_ACCESS_KEY` or `SCOPE_SELECTION_REQUIRED` | The tenant has scopes (ABAC) enabled and the access key has zero or multiple scope bindings. | Bind the key to exactly one scope, or set the `VEGA_SCOPE_ID` repository variable to the scope UUID the sync should use. |
| Every query fails with 403 `SCOPE_SELECTION_REQUIRED` — `Invalid X-Vega-Scope header value` | `VEGA_SCOPE_ID` is set but is not a UUID. | Copy the scope's UUID exactly; a name or a truncated id is rejected before any permission check. |
| Every query fails with 403 `ACCESS_DENIED` right after setting `VEGA_SCOPE_ID` | The UUID is well-formed but the access key has no binding to that scope. | Point `VEGA_SCOPE_ID` at a scope the key is actually bound to, or add the binding to the key. |
| A skill fails with `the name ... is already used by a skill this repo does not manage` | A skill with that name was made in the Vega UI. Syncing would overwrite it. | Rename the `SKILL.md` skill, or rename or delete the UI skill. |
| Every skill fails with `ACCESS_DENIED ... AgentsWrite` | The access key cannot write skills. | Give the key the `AgentsWrite` permission, or remove the `skills/` folder to stop syncing skills. |
| A detection fails with `skillIds names skill(s) ... that are not in the tenant` | A skill it uses failed to sync in the same run, so the detection was held back. | Fix the skill's error; the detection syncs on the next run. |
| A detection fails because a skill id does not exist | Its `skillIds` names a skill whose `SKILL.md` was deleted, or a mistyped id. | Remove the id from `skillIds`. |
| Sync fails with `memories are not available to this access key` | Memories are not enabled for your organization, or the key lacks `AgentsRead` or `LabelsRead`. | Ask Vega to enable memories, or remove the `memories/` folder to stop syncing them. |
| A memory fails with `label(s) not found in the tenant` | A name under `labels` does not exist yet. | Create the label in the Vega UI, or remove it from the file. |
| A memory fails with `MEMORY_LIMIT_REACHED` | The tenant would pass 250 active memories. The count includes memories written in the UI and learned by Vega. | Disable or delete memories you no longer need, in the repository or the UI, then re-run. |
| A memory fails with `a memory with this title already exists without the 'detections-as-code' label` | Someone removed the label in the UI, or wrote a memory with the same title there. The sync no longer manages it and will not create a duplicate. | Add the `detections-as-code` label back to that memory in the UI to hand it to the sync, or delete it. |
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

- **Custom detections only.** This template manages tenant-custom detections authored as YAML in this repository. Vega's built-in library detections are not in scope; manage those through the Vega UI. The sync never deletes a library detection, even though the API lists them next to the custom ones.
- **No drift detection.** The sync workflow runs on pushes to `main` that touch `detections/**`, `skills/**`, `memories/**` or `scripts/**`, and on manual dispatch. Changes made to a synced detection through the Vega UI between repository syncs persist silently and are reverted to the YAML state on the next sync. There is no warning, alert, or reconciliation report for UI-side edits. Treat the repository as the single source of truth, and run the **Sync ALL detections, skills and memories** workflow periodically to force-reconcile if UI edits are suspected.
- Lookups and data sources must already exist in the tenant.
- A merge that fails partway through leaves the tenant in a partially-applied state. Re-running the workflow after fixing the offending YAML converges (idempotent).
- The Access Key currently requires **Administrator** role; fine-grained scoping is not yet supported.
- `deleteDetection` is a single-detection API; deletes run one rule at a time. Creates and updates batch in chunks of 100.
- Skills sync the `SKILL.md` body only; other files in a skill's folder are not uploaded. Skill labels are managed in the Vega UI. Vega library skills are read-only: clone one in the UI to change it.
- Memories are matched by title, so renaming one replaces it and resets its usage history. Memories Vega proposes for review (pending review) are not managed here; approve or ignore them in the UI.
