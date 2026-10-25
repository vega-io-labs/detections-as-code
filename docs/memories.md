# Memory YAML - Field Reference

Reference for every field in a Vega memory YAML. For an overview, see the
top-level [README](../README.md#memories). For a starter file ready to copy,
see [docs/memory.template.yaml](memory.template.yaml), and for a worked
example, [docs/example-memory.yaml](example-memory.yaml).

A memory is a note about your environment that Vega agents read when they
triage alerts and investigate incidents: known benign activity, the owner of
an asset, an accepted risk, a standing instruction. Agents decide whether a
memory applies from its `title` and `description`, then read `content`.

## File location and discovery

Memory YAMLs reside under `memories/`. The sync engine reads
`memories/**/*.yaml` and `memories/**/*.yml` recursively. The subdirectory
layout and the filename are for your own organisation.

One memory per file.

If the repository has no `memories/` folder, memories are not synced at all:
the sync never reads, changes or deletes a memory in that case. An empty
`memories/` folder is different: it means the repository manages zero
memories, so the sync deletes any memory it created before.

## How the sync recognises its memories

Memories have no external id, so the sync relies on two things:

1. **The `detections-as-code` label.** The sync creates this label the first
   time it creates a memory, and attaches it to every memory it writes. It
   only ever reads, updates and deletes memories that carry the label.
   Memories written in the Vega UI and memories Vega learns from analyst
   verdicts are never touched.
2. **The title.** Among the labelled memories, a file is matched to the
   memory with the same `title`. Titles must therefore be unique across
   `memories/`; the PR check enforces it.

Two consequences:

- **Renaming a title replaces the memory.** The old memory is deleted and a
  new one is created. The new memory gets a new `MEM-` id and starts with an
  empty usage history.
- **Removing the label in the UI releases the memory.** The sync no longer
  manages it, and the file is blocked rather than created a second time. Add
  the label back to hand the memory to the sync again, or delete the file if
  the memory should go.

## Field reference

### `title` - required, string

Short title, 1-150 characters. Unique across `memories/`. This is the
identity of the memory, so pick a title that will not need to change.

```yaml
title: "Approved vulnerability scanner scanner-01"
```

### `description` - required, string

One-line summary, 1-300 characters, no line breaks. Agents read it to decide
whether the memory applies to what they are looking at, so say when it
applies rather than repeating the title.

```yaml
description: "Weekly authenticated vulnerability scans from scanner-01 (192.0.2.10) are expected and approved."
```

A long line can be folded with `>-`, which joins the lines with spaces:

```yaml
description: >-
  Weekly authenticated vulnerability scans from scanner-01 (192.0.2.10)
  are expected and approved.
```

### `content` - required, string

The full note, 1-5000 characters. Use a `|-` block scalar for multiple
lines. Good memories state what is expected, who owns it, and what would make
the same activity suspicious after all, so an agent can still escalate
activity that falls outside the memory.

```yaml
content: |-
  scanner-01 runs authenticated scans every Sunday 02:00-06:00 UTC.

  Not covered, escalate instead:
  - Any activity from 192.0.2.10 outside the Sunday window.
```

### `status` - optional, string, default `enabled`

| Value | Effect |
|---|---|
| `enabled` | Vega agents use the memory. |
| `disabled` | The memory stays in the tenant, but agents do not use it. |

Quote the value or write it in lowercase: an unquoted `on`/`off`/`yes`/`no`
is read as a boolean by YAML and rejected.

### `expiresAt` - optional, ISO 8601 date or time

After this time Vega agents stop using the memory and its status reads
`EXPIRED`. Omit it for a memory that does not expire. A date without a time
means midnight UTC; a time without an offset is read as UTC.

```yaml
expiresAt: "2027-01-31"                 # midnight UTC
expiresAt: "2027-01-31T18:00:00Z"
expiresAt: "2027-01-31T20:00:00+02:00"
```

The API refuses to create a memory that has already expired, so a past date
is a warning at PR time and an error at sync time for a new memory. For an
existing memory it is accepted and expires it. Removing the key removes the
expiration.

### `entities` - optional, list, default `[]`

What the memory is about. At most 50 entries, each with a `type` and a
`value` (1-512 characters).

| `type` | Example `value` |
|---|---|
| `account` | `svc-vulnscan@example.com` |
| `device` | `scanner-01` |
| `ip` | `192.0.2.10` |
| `domain` | `updates.example.com` |

```yaml
entities:
  - type: device
    value: "scanner-01"
  - type: ip
    value: "192.0.2.10"
```

Values are matched without regard to case, so two entries that differ only
in case are rejected as duplicates. For the same reason a change that only
alters case is not pushed to the tenant. The list replaces what is attached
in the tenant on every sync.

### `labels` - optional, list of strings, default `[]`

Names of labels to attach. The labels must already exist in your tenant
(create them in the Vega UI); a missing label blocks that one memory and the
run reports it. Names match without regard to case.

Do not list `detections-as-code`: the sync adds it to every memory it
manages. The list replaces the labels attached in the UI on every sync.

## Limits

| Limit | Value | Checked |
|---|---|---|
| `title` | 1-150 characters | PR |
| `description` | 1-300 characters, one line | PR |
| `content` | 1-5000 characters | PR |
| `entities` | at most 50, value 1-512 characters | PR |
| Active memories per tenant | 250 | PR checks the repository's enabled memories; the sync reports `MEMORY_LIMIT_REACHED` when the tenant total, which includes UI and learned memories, would pass it |

## What the PR-time lint checks

| Check | Failure mode |
|---|---|
| YAML parses and is a mapping | PR red |
| `title`, `description`, `content` present, non-empty and within their limits | PR red, field named |
| `description` is a single line | PR red |
| Unknown keys (`enabled`, `name`, `id`, `labelIds`, typos) | PR red, with the right field named where there is one |
| `status` is `enabled` or `disabled` | PR red |
| `expiresAt` parses as ISO 8601 | PR red |
| `expiresAt` in the past | PR yellow, warning only |
| `entities` types, value lengths, at most 50, no case-insensitive duplicates | PR red |
| `labels` non-empty, unique, without `detections-as-code` | PR red |
| Titles unique across `memories/` | PR red |
| At most 250 enabled memories in `memories/` | PR red |
| A title changed in this PR (a rename replaces the memory) | PR yellow, warning only |

## Validated at sync time (post-merge)

| Behaviour | Where it fails |
|---|---|
| Memories are enabled for your organization and the access key may use them | The run stops the memory step with `memories are not available to this access key` |
| Every name in `labels` exists in the tenant | That memory is reported as blocked; the others still sync |
| The tenant stays within 250 active memories | `createMemoryPublic` / `updateMemoryPublic` reject with `MEMORY_LIMIT_REACHED` |
| A file's title is not held by a memory without the `detections-as-code` label | That memory is reported as blocked; the others still sync |

## Permissions

The access key needs four permissions to sync memories:

| Permission | Used for |
|---|---|
| `AgentsRead` | Reading the tenant's memories |
| `LabelsRead` | Reading the tenant's labels, to resolve each file's `labels` and find the `detections-as-code` label |
| `AgentsWrite` | Creating, updating and deleting memories |
| `LabelsWrite` | Creating the `detections-as-code` label on the first sync |

Without either read permission the run reports `memories are not available to this access key`. Without `LabelsWrite` the first creates fail and say so.
