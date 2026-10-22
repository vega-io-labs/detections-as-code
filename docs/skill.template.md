---
# Copy this file to skills/<category>/<skill-name>/SKILL.md.
# Full reference: docs/skills.md

# A UUID you generate once and never change:
#   python3 -c 'import uuid; print(uuid.uuid4())'
id: "00000000-0000-4000-8000-000000000000"

# 1-255 characters, unique in your tenant.
name: "Skill Name"

# When to use the skill. The agent picks skills by name and description.
description: "What this skill covers, which alert or case should load it, and where it stops."

# triage | investigation | tuning | hunting | exploration | detection_generation | memory
type: "triage"
---

# Steps

Everything below the closing `---` is the skill's instructions, at most 500 lines.
