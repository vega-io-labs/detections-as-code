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
uuidgen -7                                              # macOS 14+ / util-linux 2.39+
python -c "import uuid; print(uuid.uuid7())"            # Python 3.14+
```

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

```yaml
state: "test_mode"
```

### `frequencyCron` - required, string

Schedule on which the detection runs.

- **Type:** string
- **Required:** yes
- **Format:** Vega cron syntax. The shortest form is `Nm` / `Nh` / `Nd`.
- **Note:** the API may normalise this value on storage (e.g. `60m` is stored as `@every 60m`).

```yaml
frequencyCron: "15m"
```

### `lookBackSeconds` - required, int

Query lookback window, in seconds. Specifies the time range each run evaluates against.

- **Type:** int
- **Required:** yes
- **Constraint:** must be > 0

```yaml
lookBackSeconds: 900     # 15 minutes
```

### `mitreTechniques` - optional, list of strings, default `[]`

MITRE ATT&CK technique IDs this detection covers.

- **Type:** list of strings
- **Required:** no
- **Default:** `[]`
- **Convention:** list the most specific applicable subtechnique only. Including both the parent (`T1078`) and the child (`T1078.004`) is redundant.
- **Note:** Tactics are derived server-side from techniques. Do not list tactics in the YAML.

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

### `groupingFields` - optional, list of strings, default `[]`

Result fields used to group hits in a single alert (instead of producing
one alert per matching event).

- **Type:** list of strings
- **Required:** no
- **Default:** `[]`
- **Format:** OCSF dotted paths, e.g. `actor.user.name`, `src_endpoint.ip`

```yaml
groupingFields: ["actor.user.name"]

groupingFields:
  - "actor.user.name"
  - "src_endpoint.ip"
```

### `groupingDurationSeconds` - optional, int, default `null`

Time window over which `groupingFields` is applied.

- **Type:** int (seconds) or `null`
- **Required:** no
- **Default:** `null`

```yaml
groupingDurationSeconds: 3600
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
- **Constraints:** at least one cell, exactly one with `trigger: true`, names unique and must not start with `@`.
- **Alias:** `detectionCells:` is accepted as a synonym for `cells:` for compatibility with YAMLs copied from internal Vega repositories.

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
| `groupingField` (singular) / `groupingThreshold` | Event-grouping feature; not in v1. |

## What the PR-time lint actually checks

| Check | Mechanism | Failure mode |
|---|---|---|
| YAML parses | `yaml.safe_load` | PR red, parse error shown |
| All required fields present and non-empty (`id`, `name`, `severity`, `state`, `frequencyCron`, `lookBackSeconds`, and exactly one of `query` or `cells`) | translator | PR red, missing field named |
| `id` matches `^[a-z0-9][a-z0-9._-]{0,127}$` | translator | PR red, regex shown |
| `name` length 1-200 | translator | PR red |
| `severity` is `1-4` or `LOW/MEDIUM/HIGH/CRITICAL` | translator | PR red |
| `state` is `enabled/disabled/test_mode` (also accepts `test` / `test-mode` aliases) | translator | PR red |
| `lookBackSeconds > 0` | translator | PR red |
| Exactly one of `query` / `cells` is present (not both, not neither) | translator | PR red |
| Multi-cell with exactly one trigger cell, names unique and not starting with `@` | translator | PR red |

## Validated at sync time (post-merge)

| Field / behaviour | Where it would fail |
|---|---|
| KQL parses | `createDetections` rejects with parser error in the sync run's step summary |
| KQL references data sources / lookups that exist in your tenant | `createDetections` rejects with `table selectors not found: @X` |
| `frequencyCron` format | `createDetections` rejects unparseable cron |
| `mitreTechniques` validity (must be real T-codes) | `createDetections` rejects fake technique IDs |
| KQL semantic correctness (does it match the right events?) | Runtime (you'll see it in detection hits or lack of them) |
