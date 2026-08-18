# Detection YAML - Field Reference

Comprehensive reference for every field in a Vega detection YAML. For an
overview, see the top-level [README](../README.md). For a starter file
ready to copy, see [docs/detection.template.yaml](detection.template.yaml).

## File location and discovery

Detection YAMLs reside under `detections/`. The sync engine reads
`detections/**/*.yaml` and `detections/**/*.yml` recursively. The
subdirectory layout is for organisational use only; the filename is for
human readability, and the `id` field inside the YAML binds the file to
the detection in Vega.

One detection per file.

## YAML value conventions

| Concept | Empty | Single value | Multiple values |
|---|---|---|---|
| String | `""` or omit | `"login"` (or unquoted: `login`) | n/a |
| Integer | `null` or omit | `300` | n/a |
| Boolean | n/a | `true` / `false` | n/a |
| List (inline) | `[]` | `["one"]` | `["one", "two"]` |
| List (block) | (use inline `[]`) | `- one` | `- one`<br>`- two` |
| Multi-line string | (use `""`) | `\|-` block scalar (strips trailing newline) | n/a |

A multi-line string with `|-` (block scalar, strip trailing newline):

```yaml
logicDescription: |-
  First line.
  Second line.
```

## Field reference

### `id` - required, string

Stable identifier that binds the YAML to a detection in your Vega tenant.
Maps to the API's `externalId`.

- **Type:** string
- **Required:** yes
- **Constraints:** regex `^[a-z0-9][a-z0-9._-]{0,127}$` (lowercase, alphanumeric, `.`, `_`, `-`; 1-128 characters; must start with a letter or digit)
- **Recommended:** UUID v7 (time-ordered, lowercase, matches the regex)
- **Permanent:** once synced, this id is reserved permanently in your tenant - deleting the YAML does not free the id

```yaml
id: "019e206b-17d9-75d6-97a4-b08750a5ef3c"      # placeholder; generate your own
```

Generate one:
```bash
# Python 3.14+
python3 -c "import uuid; print(uuid.uuid7())"

# any Python 3
python3 -c "import os,time,uuid; b=bytearray(os.urandom(16)); b[0:6]=int(time.time()*1000).to_bytes(6,'big'); b[6]=(b[6]&0x0f)|0x70; b[8]=(b[8]&0x3f)|0x80; print(uuid.UUID(bytes=bytes(b)))"

# util-linux 2.39+ (Linux only)
uuidgen -7
```

macOS `uuidgen` is not usable for this: it has no `-7` flag, and its output is an
uppercase version 4 UUID, which the lowercase-only `id` regex rejects.

### `name` - required, string

Human-readable detection name. Shown in the Vega UI and in alerts.

- **Type:** string
- **Required:** yes
- **Constraints:** 1-200 characters

```yaml
name: "Root Account Console Login"
```

### `severity` - required, int or enum string

The severity level assigned to a detection match.

- **Type:** int (`1-4`) or string (`"LOW"`, `"MEDIUM"`, `"HIGH"`, `"CRITICAL"`)
- **Required:** yes (no default; must be specified explicitly)
- **Mapping:** `1 = LOW`, `2 = MEDIUM`, `3 = HIGH`, `4 = CRITICAL`

```yaml
severity: 4
# or equivalently:
severity: "CRITICAL"
```

### `state` - required, string

Lifecycle state of the detection. Required so that the enabled / disabled
status is set explicitly: silent defaults on security infrastructure
introduce risk.

- **Type:** string
- **Required:** yes
- **Allowed values:** `enabled`, `disabled`, `test_mode`
  - `enabled` - runs on schedule; resulting alerts feed incidents
  - `disabled` - does not run
  - `test_mode` - runs on schedule; resulting alerts are isolated from incident correlation, used to validate tuning against production data
- **Accepted aliases:** comparison is case-insensitive; `test` and `test-mode` both resolve to `test_mode`. Prefer the canonical values above so the YAML round-trips cleanly against `git blame`.
- **Note:** `createDetections` does not accept a state, so the sync creates
  every detection enabled and applies `disabled` / `test_mode` in a follow-up
  call reported as a `set_state` row. A rule first synced as `disabled` is
  therefore enabled for the few seconds between the two calls.

```yaml
state: "test_mode"
```

### `frequencyCron` - required, string

Schedule on which the detection runs.

- **Type:** string
- **Required:** yes
- **Accepted forms:**
  - Interval shorthand: minutes and/or hours, hours first - `5m`, `1h`,
    `1h30m`. Seconds and days are **not** interval units: write `2m` rather
    than `120s`, and `24h` rather than `1d`.
  - Standard 5-field cron: `*/15 * * * *`
  - Cron macro: `@every 90m`, `@hourly`, `@daily`
- **Constraint:** the resulting interval must be between 1 minute and 31 days
- **Note:** interval shorthand is normalised on storage - `60m` reads back as
  `@every 60m`. The reconciler compares the resolved interval, so `1h` and
  `60m` are treated as the same schedule and neither produces a phantom
  update.

```yaml
frequencyCron: "15m"
```

### `lookBackSeconds` - required, int

Query lookback window, in seconds. Specifies the time range each run evaluates against.

- **Type:** int
- **Required:** yes
- **Constraints:** must be **>= the `frequencyCron` interval** and <= 31 days
  (`2678400`). A lookback shorter than the schedule would leave unexamined
  gaps between runs, so the API rejects it.
- **Guidance:** set it equal to the interval for a plain sliding window, or
  larger when the query needs history (a chain cell correlating over an hour,
  a rate check counting events across several runs).

```yaml
frequencyCron: "15m"
lookBackSeconds: 900     # 15 minutes - one window per run, no gaps, no overlap
```

### `mitreTechniques` - optional, list of strings, default `[]`

MITRE ATT&CK technique IDs this detection covers.

- **Type:** list of strings
- **Required:** no
- **Default:** `[]`
- **Format:** `T` + four digits, optionally `.` + three digits for a
  subtechnique (`T1078`, `T1078.004`). Tactic IDs (`TA0001`) are not accepted.
- **Convention:** list the most specific applicable subtechnique only. Including both the parent (`T1078`) and the child (`T1078.004`) is redundant.
- **Note:** Tactics are derived server-side from techniques. Do not list tactics in the YAML.
- **Note:** each ID is checked against the tenant's ATT&CK catalogue at sync
  time; an unknown technique fails the batch.

```yaml
# Empty
mitreTechniques: []

# Single subtechnique
mitreTechniques: ["T1078.004"]

# Multiple distinct subtechniques (block list form)
mitreTechniques:
  - "T1003.001"
  - "T1003.002"
  - "T1003.006"
```

### `logicDescription` - optional, string

Literal description of the query's match conditions. Shown in the Vega
UI during triage to answer "what does this rule match?".

- **Type:** string
- **Required:** no (defaults to empty string)
- **Style:** 2-4 sentences. Identify the data source, the event types
  selected, and the fields under evaluation. Restrict the content to
  query mechanics; leave the threat-model framing for `attackScenario`.

```yaml
logicDescription: "Matches AWS CloudTrail ConsoleLogin events where the actor is the account root user."
```

### `attackScenario` - optional, string

Threat-model rationale for the detection. Written from the adversary's
perspective to answer "why does this match indicate malicious activity?".

- **Type:** string
- **Required:** no (defaults to empty string)
- **Style:** 2-4 sentences. State the attacker's objective and explain
  how the matched events advance it. Keep separate from the literal
  query description in `logicDescription`; conflating the two weakens
  both fields.

```yaml
attackScenario: "An adversary with stolen AWS root credentials logs in to the console to perform privileged actions outside normal scoped-IAM access patterns. Root logins are exceedingly rare in healthy environments, so any root login warrants investigation."
```

### `references` - optional, list of strings, default `[]`

URLs supporting the detection (vendor best-practice docs, MITRE ATT&CK
technique pages, CVE write-ups, threat-intelligence briefings).

- **Type:** list of strings
- **Required:** no
- **Default:** `[]`

```yaml
references: []

references: ["https://attack.mitre.org/techniques/T1078/004/"]

references:
  - "https://attack.mitre.org/techniques/T1078/004/"
  - "https://example.com/internal-runbook"
```

### Two ways to reduce alert volume

Deduplication and burst protection sound alike and are configured separately:

| | Deduplication | Burst protection |
|---|---|---|
| Fields | `deduplicationFields`, `deduplicationWindowSeconds` | `groupingField`, `groupingThreshold` |
| Scope | Across runs, while an alert is open | Within a single run |
| Effect | A repeat match updates the open alert instead of opening a new one | A run above the threshold collapses into grouped alerts |

They compose: deduplication runs first, and burst protection then applies to
whatever survived it.

> **Removed fields.** `groupingFields` and `groupingDurationSeconds` were
> dropped from the detection API. Neither ever affected how alerts were
> produced, so a YAML carrying them never actually grouped anything, and the
> sync now rejects them instead of remapping them silently.
>
> `groupingDurationSeconds` maps cleanly onto `deduplicationWindowSeconds` -
> same window, new name. `groupingFields` does **not** have a single
> successor: it was dropped as an unfinished piece of deduplication, but the
> plural name has since been reused internally for the multi-field form of
> burst protection. Pick by intent, not by the similar name:
> `deduplicationFields` if you wanted repeat alerts folded into an open one,
> `groupingField` if you wanted one noisy run split up. Either way the
> setting starts doing something it never did before.

### `deduplicationFields` - optional, list of strings, default `[]`

Result fields used to suppress duplicate alerts. New events that match an
active alert on every listed field update that alert instead of opening a
new one.

- **Type:** list of strings
- **Required:** no
- **Default:** `[]` - with a window set but no fields, every matching event in
  the window folds into one alert
- **Format:** OCSF dotted paths, e.g. `actor.user.name`, `src_endpoint.ip`
- **Note:** order does not matter; the fields form a set.

```yaml
deduplicationFields: ["actor.user.name"]

deduplicationFields:
  - "actor.user.name"
  - "src_endpoint.ip"
```

### `deduplicationWindowSeconds` - optional, int, default `0`

Time window over which `deduplicationFields` is applied. Deduplication is off
until this is set.

- **Type:** int (seconds)
- **Required:** no
- **Default:** `0` (deduplication disabled)
- **Constraint:** 0 to `86400` (24 hours)

```yaml
deduplicationFields: ["actor.user.name"]
deduplicationWindowSeconds: 3600
```

### `groupingField` - optional, string, default `null`

Burst protection. When a single detection run returns more rows than
`groupingThreshold`, results are grouped into one alert per distinct value
of this field instead of one alert per row. Pick the field that stays
constant across the blast: the acting principal for endpoint/identity/cloud
detections, the source for scans and sprays.

- **Type:** string (a single normalized field name)
- **Required:** no
- **Default:** `null` - over the threshold, the entire run collapses into one
  alert
- **Note:** validated against the tenant's normalized-field catalog at sync
  time; an unknown field fails the whole batch.

```yaml
groupingField: "actor.user.name"
```

### `groupingThreshold` - optional, int, default `10`

Row count in a single run that activates burst protection. Independent of
`groupingField`: on its own it is the point at which a noisy run collapses
into a single alert; with a `groupingField` it is the point at which the run
is split by that field instead.

- **Type:** int, range 2-100
- **Required:** no
- **Default:** `10` (tenant-configurable, so omitting it and pinning it to
  `10` are not the same thing)

```yaml
groupingField: "src_endpoint.ip"
groupingThreshold: 25
```

> **Neither can be cleared through the API.** An omitted `groupingField` /
> `groupingThreshold` is indistinguishable from an explicit null, and the API
> reads both as "leave unchanged". Deleting the keys from a YAML therefore
> leaves the previous values in place; the reconciler stops tracking them
> rather than reporting a diff it can never resolve. Clear them in the Vega
> UI, or set an explicit new value.

### `actorFields` / `targetFields` - optional, list of strings, default `[]`

Priority-ordered field names used to extract the alert's Actor and Target
entities, highest priority first: the first field with a value in the result
row wins. Empty falls back to Vega's per-data-type defaults.

- **Type:** list of strings
- **Required:** no
- **Default:** `[]`
- **Constraints:** at most 5 entries each; every entry must be a normalized
  field available in your tenant, validated at sync time
- **Note:** order is meaningful - reordering the list is a real change and
  produces a new detection version.

```yaml
actorFields:
  - "actor.user.name"
  - "actor.process.user.name"
targetFields:
  - "device.hostname"
```

### `query` or `cells` - required (exactly one of them)

The detection's KQL. Use the **`query`** shorthand for the single-cell case. Use **`cells`** for multi-step correlations.

#### Single-cell (`query`)

- **Type:** string (multi-line)
- **Format:** starts with a data source selector (e.g. `@CloudTrail`), then chains `|`-separated operators.

```yaml
query: |-
  @CloudTrail
  | where event_name =~ "ConsoleLogin"
  | where actor.user.type =~ "Root"
```

#### Multi-cell (`cells`)

A list of named query fragments with exactly one designated as the trigger. The trigger cell unions or joins the others using `@CellName` references. Cells may also reference each other (chained composition), not only the trigger.

- **Type:** list of `{name, query, trigger?}`
- **Constraints:** at least one cell, exactly one with `trigger: true`, names unique and non-empty. A **new** detection additionally has its cell names restricted to letters, digits, spaces, `_` and `-` by the create API; the update path does not re-check, so detections that predate the rule keep other characters and stay manageable here. The PR check flags the difference as a warning rather than an error, because it cannot tell a create from an update without tenant access.
- **Alias:** `detectionCells:` is accepted as a synonym for `cells:` for compatibility with YAMLs copied from internal Vega repositories.
- **Note:** write cell references as `@CellName`. Vega rewrites them into a canonical `@cells:<ref>/CellName` form on save, so the UI and the API show the longer version - that is the same reference, and the reconciler compares the two as equal rather than rewriting your detection on every sync.

See the four annotated patterns in `docs/`:

- [`example-single-cell.yaml`](example-single-cell.yaml) - single-cell baseline
- [`example-multi-cell-exclusion.yaml`](example-multi-cell-exclusion.yaml) - anti-join exclusion
- [`example-multi-cell-or.yaml`](example-multi-cell-or.yaml) - N state cells composed by trigger via OR (union)
- [`example-multi-cell-chain.yaml`](example-multi-cell-chain.yaml) - cells pipe into one another

```yaml
cells:
  - name: "cred-tool-execution"
    query: |-
      @EDR-Events
      | where file.path has_any ("mimikatz.exe", "mimi.exe")
  - name: "lsa-dump-cmdline"
    query: |-
      @EDR-Events
      | where process.cmd_line contains "lsadump::sam"
  - name: "trigger"
    trigger: true
    query: |-
      @cred-tool-execution, @lsa-dump-cmdline
```

#### Referencing data sources

| Form | Notes |
|---|---|
| `@CloudTrail` | Data source display name with spaces replaced by hyphens. |
| `@Okta-System-Logs` | Same convention. |
| `@lookup_tables:<refName>/<title>` | Lookup tables; must be created in the Vega UI first. |

Only data sources with a configured connector in your tenant are
queryable. The sync workflow's `createDetections` call rejects detections
that reference data sources that are not connected.

## Fields the YAML schema does NOT expose

| Field | Why omitted |
|---|---|
| `mitreTactics` | Derived server-side from `mitreTechniques`. |
| `dataSourcesIds` | Derived from the table selector in the KQL itself (e.g. `@CloudTrail`). |
| `tags` | Managed in the Vega UI. |

## What the PR-time lint actually checks

Everything below mirrors a rule the API enforces on **both** the create and
the update path. Catching it in the PR matters because a sync batch is
transactional: one rejected detection rolls back every other detection sent in
the same call. Rules that only bind on create are reported as warnings, since
the check runs without tenant access and cannot tell which a YAML will become.

| Check | Mechanism | Failure mode |
|---|---|---|
| YAML parses | `yaml.safe_load` | PR red, parse error shown |
| All required fields present and non-empty (`id`, `name`, `severity`, `state`, `frequencyCron`, `lookBackSeconds`, and exactly one of `query` or `cells`) | translator | PR red, missing field named |
| `id` matches `^[a-z0-9][a-z0-9._-]{0,127}$` | translator | PR red, regex shown |
| `name` length 1-200 | translator | PR red |
| `severity` is `1-4` or `LOW/MEDIUM/HIGH/CRITICAL` | translator | PR red |
| `state` is `enabled/disabled/test_mode` (also accepts `test` / `test-mode` aliases) | translator | PR red |
| `frequencyCron` is a recognised shape and resolves to 1m-31d | translator | PR red, accepted forms listed |
| `lookBackSeconds` >= the `frequencyCron` interval and <= 31 days | translator | PR red |
| `deduplicationWindowSeconds` within 0-86400 | translator | PR red |
| `groupingThreshold` within 2-100 | translator | PR red |
| `actorFields` / `targetFields` at most 5 non-empty entries each | translator | PR red |
| `mitreTechniques` entries look like `T1078` / `T1078.004` | translator | PR red |
| Removed fields (`groupingFields`, `groupingDurationSeconds`) are not used | translator | PR red, replacement named |
| Exactly one of `query` / `cells` is present (not both, not neither) | translator | PR red |
| Multi-cell with exactly one trigger cell, names unique and non-empty | translator | PR red |
| Cell names outside `[A-Za-z0-9 _-]` | translator | PR yellow - warning only, fatal only if the detection is new |

## Validated at sync time (post-merge)

Anything that needs tenant state cannot be checked in a PR (the validate
workflow runs without a tenant secret, so it also passes on fork PRs).

| Field / behaviour | Where it would fail |
|---|---|
| KQL parses | `createDetections` rejects with parser error in the sync run's step summary |
| KQL references data sources / lookups that exist in your tenant | `createDetections` rejects with `table selectors not found: @X` |
| Cron expressions and macros that need a full cron parser (`*/15 * * * *`, `@daily`) | `createDetections` rejects an unparseable expression |
| `mitreTechniques` exist in the ATT&CK catalogue | `createDetections` rejects unknown technique IDs |
| `groupingField`, `actorFields`, `targetFields` are normalized fields in your tenant | `createDetections` rejects with `... is not a valid normalized field` |
| KQL semantic correctness (does it match the right events?) | Runtime (you'll see it in detection hits or lack of them) |
