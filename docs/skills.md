# Skills reference

A skill is a set of instructions Vega agents follow for one kind of work: how to triage a class of alert, how to investigate an incident, how to tune a noisy detection, how to hunt. Vega ships a library of skills; the ones you write live in your tenant next to them. This repository manages the skills you write.

Each skill is one folder under `skills/` holding a `SKILL.md` file. The subfolder layout is up to you; the sync reads `skills/**/SKILL.md`:

```
skills/
  triage/
    service-account-sign-in/
      SKILL.md
  investigation/
    payroll-access/
      SKILL.md
```

Start from [`skill.template.md`](skill.template.md), or read the worked example in [`example-skill.md`](example-skill.md).

## File format

A `SKILL.md` is YAML frontmatter between two `---` lines, then the instructions in Markdown. This is the same layout as the Agent Skills format and as Vega's own library skills.

```markdown
---
id: "8b0f5a3e-2c4d-4e6f-9a1b-3c5d7e9f1a2b"
name: "Service Account Sign-In Triage"
description: "Sign-ins by service accounts from outside their fixed egress range. Use when a detection fires on a non-human identity authenticating from a new IP, country or client."
type: "triage"
---

# Triage steps

1. Compare the source IP with the account's documented egress range.
2. ...
```

## Fields

| Field | Required | Rules |
|---|---|---|
| `id` | yes | A UUID you generate once. It links the file to its skill in Vega and must never change. |
| `name` | yes | 1-255 characters, unique across `skills/` and among the skills in your tenant. |
| `description` | yes | 1-5000 characters. |
| `type` | yes | `triage`, `investigation`, `tuning`, `hunting`, `exploration`, `detection_generation` or `memory`. |
| body | yes | Everything after the closing `---`: the instructions. At most 500 lines and 500000 characters. |

No other keys are accepted. Files copied from the Vega library carry `category`, `version`, `author` and `tags`; the PR check names each one and says what to do with it.

### `id`

Generate it once, when you create the file:

```bash
python3 -c 'import uuid; print(uuid.uuid4())'
```

The `id` is how the sync finds the skill again, so the name, description, type and instructions can all change and the skill is updated in place: same skill in Vega, same detections attached. Changing the `id` deletes the skill and creates a new one, which drops it from every detection that used it.

Vega stores the id in lowercase with hyphens. Any other spelling of the same UUID is read as that one.

### `name`

What analysts see in the Vega UI and what the agent sees next to the description. The server does not keep names unique, but `createSkills` matches an existing skill by name, so a new file named like a skill already in the tenant would adopt that skill. The sync blocks it instead. Rename one of the two. Two files in this repository cannot share a name either, since they would end up as one skill.

### `description`

The agent picks skills by name and description, so write it as when to use the skill: what it covers, the alert or case that should load it, and where it stops ("not for X"). A vague description is a skill that never gets used.

### `type`

Which agentic workflow loads the skill:

| `type` | Used when |
|---|---|
| `triage` | Vega triages an alert. Triage skills can be attached to detections. |
| `investigation` | Vega investigates an incident. Investigation skills can be attached to detections. |
| `tuning` | Vega suggests exclusions for a noisy detection. |
| `hunting` | A threat hunt. |
| `exploration` | Exploring data with the agent. |
| `detection_generation` | Turning a source (a SIEM rule, an ATT&CK technique) into detection behaviours. |
| `memory` | How the agent writes and changes tenant memories. |

The value is case-insensitive.

### The instructions

Plain Markdown: steps, the leads that point to a real threat, the benign context that rules it out, the queries worth running. Leading and trailing blank lines are dropped, so reformatting the end of a file is not a change.

Only `SKILL.md` is read. Other files in a skill's folder (notes, references, scripts) stay in git and are not uploaded; put everything the agent needs in the body.

## Attaching a skill to a detection

A detection's `skillIds` takes the ids of triage or investigation skills. For a skill in this repository, use the `id` from its `SKILL.md`:

```yaml
# detections/identity/service-account-new-egress.yaml
skillIds:
  - "8b0f5a3e-2c4d-4e6f-9a1b-3c5d7e9f1a2b"   # skills/triage/service-account-sign-in
```

Vega gives the skill its own id when it is created, so the sync looks it up and sends that one. Skills sync before detections, so a new skill and the detection that uses it can land in the same pull request. Ids of skills that are not in this repository (a library skill, a skill made in the UI) are passed through as they are.

The PR check rejects a repository skill of any other type in `skillIds`. If a skill fails to sync, the detections that name it are held back in that run, so they are neither written without it nor able to fail the rest of their batch.

## How the sync treats skills

- **It manages every skill in the tenant that has an `id` (externalId).** That is how it recognises the skills it wrote, the same rule as detections. Skills made in the Vega UI have no `id`, and Vega library skills are read-only, so the sync never changes or deletes either. A skill some other tool or repository created through the API with an `externalId` does count as managed: if it has no `SKILL.md` here, the sync deletes it. Keep one repository per tenant for skills.
- **The file is the source of truth.** Name, description, type and instructions are compared with the tenant on every run, and edits made in the UI are reverted on the next sync. Unchanged skills are skipped.
- **Labels stay in the UI.** The sync never sends labels, so the labels you put on a skill in Vega are kept.
- **Deleting the folder deletes the skill** on the next sync (unless `--no-deletes`). Remove its id from every detection's `skillIds` in the same pull request: the PR check fails while a detection still names it, and a detection that does fails to sync.
- **A missing `skills/` folder turns skill sync off.** The template does not ship one; create it with your first skill. An empty folder means "manage zero skills" and deletes any skill this repository created earlier.
- **Batches of 100, one result per skill.** Deletes run first, then updates, then creates. Each skill is applied on its own, so one rejected skill never blocks another.
- **Use a fresh UUID for a new skill, even after a delete.** A deleted skill's id is accepted again, and Vega gives it the same tenant id as before, so detections that once used the old skill pick it back up. The sync then detaches it from any detection whose `skillIds` does not name it, but it is clearer to never reuse an id.

## Adopting skills in an existing fork

This template does not ship a `skills/` folder, so merging the update into a fork leaves skill sync off. It turns on with the first merge that adds `skills/`. Before that merge, run the **Sync ALL** workflow as a dry run on the branch and read the skill plan: any skill it plans to delete was created through the API by something other than this repository.

## Permissions

Reading skills needs the access key's query permission (`QueryRead`). Creating, updating and deleting them needs `AgentsWrite`; without it every skill write fails with `ACCESS_DENIED` and the run summary says so.
