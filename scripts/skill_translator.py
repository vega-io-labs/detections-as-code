"""Translate a SKILL.md file to Vega skill API payloads.

A skill file is YAML frontmatter followed by a Markdown body:

  ---
  id: <uuid>          -> externalId (the identity the sync matches on)
  name: ...           -> name
  description: ...    -> description
  type: triage        -> SkillType enum value
  ---
  <body>              -> instructions

Validation mirrors the server's own rules (see consts.py) so a bad value fails
the PR check rather than the post-merge sync.
"""

from __future__ import annotations

import re
import uuid
from dataclasses import dataclass
from typing import Any

import yaml

from .consts import (
    SKILL_DESCRIPTION_MAX_LEN,
    SKILL_INSTRUCTIONS_MAX_CHARS,
    SKILL_INSTRUCTIONS_MAX_LINES,
    SKILL_MANDATORY_FIELDS,
    SKILL_NAME_MAX_LEN,
    VALID_SKILL_TYPES,
    SkillType,
)

_FRONTMATTER_RE = re.compile(
    r"\A---[ \t]*\r?\n(.*?)\r?\n---[ \t]*(?:\r?\n(.*))?\Z", re.DOTALL
)

_ALLOWED_FIELDS: frozenset[str] = frozenset(SKILL_MANDATORY_FIELDS)

# Vega library skills carry these keys, so a file copied from one would
# otherwise be rejected with no idea what to do about it.
_FIELD_HINTS: dict[str, str] = {
    "category": "use 'type' (triage, investigation, tuning, ...)",
    "subType": "use 'type' (triage, investigation, tuning, ...)",
    "tags": (
        "labels on skills are managed in the Vega UI and the sync leaves "
        "them alone; remove the key"
    ),
    "labels": (
        "labels on skills are managed in the Vega UI and the sync leaves "
        "them alone; remove the key"
    ),
    "version": "the skills API stores no version; remove the key",
    "author": "the sync records its access key as the author; remove the key",
    "externalId": "use 'id'",
    "title": "skills use 'name', not 'title'",
    "instructions": (
        "the instructions are the Markdown body after the closing '---'"
    ),
}


@dataclass(frozen=True)
class SkillSpec:
    external_id: str
    name: str
    description: str
    type: SkillType
    instructions: str
    path: str = ""


def count_lines(text: str) -> int:
    if not text:
        return 0
    return text.replace("\r\n", "\n").replace("\r", "\n").count("\n") + 1


def _text(doc: dict[str, Any], key: str, max_len: int, where: str) -> str:
    value = doc.get(key)
    if value is None:
        raise ValueError(f"{where}: missing required field '{key}'")
    if not isinstance(value, str):
        raise ValueError(
            f"{where}: '{key}' must be a string, got {type(value).__name__}"
        )
    value = value.strip()
    if not value:
        raise ValueError(f"{where}: '{key}' must be a non-empty string")
    if len(value) > max_len:
        raise ValueError(
            f"{where}: '{key}' must be 1-{max_len} characters "
            f"(got {len(value)})"
        )
    return value


def _external_id(value: Any, where: str) -> str:
    if value is None:
        raise ValueError(f"{where}: missing required field 'id'")
    if not isinstance(value, str):
        raise ValueError(
            f"{where}: 'id' must be a UUID string, got {type(value).__name__}"
        )
    try:
        # The API stores the canonical spelling, so matching on anything else
        # would never find the skill again.
        return str(uuid.UUID(value.strip()))
    except ValueError:
        raise ValueError(
            f"{where}: 'id' must be a UUID, e.g. the output of "
            f"`python3 -c 'import uuid; print(uuid.uuid4())'` (got {value!r})"
        ) from None


def _skill_type(value: Any, where: str) -> SkillType:
    if value is None:
        raise ValueError(f"{where}: missing required field 'type'")
    upper = str(value).strip().upper().replace("-", "_")
    if upper not in VALID_SKILL_TYPES:
        raise ValueError(
            f"{where}: invalid type {value!r}: must be "
            f"{'|'.join(sorted(t.lower() for t in VALID_SKILL_TYPES))}"
        )
    return SkillType(upper)


def _instructions(body: str, where: str) -> str:
    text = body.strip()
    if not text:
        raise ValueError(
            f"{where}: the Markdown body after the frontmatter is the skill's "
            f"instructions and must not be empty"
        )
    if len(text) > SKILL_INSTRUCTIONS_MAX_CHARS:
        raise ValueError(
            f"{where}: instructions must be at most "
            f"{SKILL_INSTRUCTIONS_MAX_CHARS} characters (got {len(text)})"
        )
    lines = count_lines(text)
    if lines > SKILL_INSTRUCTIONS_MAX_LINES:
        raise ValueError(
            f"{where}: instructions must be at most "
            f"{SKILL_INSTRUCTIONS_MAX_LINES} lines (got {lines})"
        )
    return text


def parse_skill(raw: str, where: str) -> SkillSpec:
    match = _FRONTMATTER_RE.match(raw.lstrip("﻿"))
    if not match:
        raise ValueError(
            f"{where}: a skill file starts with YAML frontmatter between two "
            f"'---' lines, followed by the instructions"
        )
    try:
        doc = yaml.safe_load(match.group(1))
    except yaml.YAMLError as e:
        raise ValueError(f"{where}: frontmatter YAML parse: {e}") from None
    if not isinstance(doc, dict):
        raise ValueError(f"{where}: the frontmatter must be a YAML mapping")
    unknown = [key for key in doc if key not in _ALLOWED_FIELDS]
    if unknown:
        # A file copied from the library carries several of these at once, so
        # all of them are named in one go rather than one per CI run.
        problems = "; ".join(
            f"unknown field '{key}': "
            + (
                _FIELD_HINTS.get(key)
                or f"allowed fields: {', '.join(sorted(_ALLOWED_FIELDS))}"
            )
            for key in unknown
        )
        raise ValueError(f"{where}: {problems}")
    return SkillSpec(
        external_id=_external_id(doc.get("id"), where),
        name=_text(doc, "name", SKILL_NAME_MAX_LEN, where),
        description=_text(doc, "description", SKILL_DESCRIPTION_MAX_LEN, where),
        type=_skill_type(doc.get("type"), where),
        instructions=_instructions(match.group(2) or "", where),
        path=where,
    )


def to_create_input(spec: SkillSpec) -> dict[str, Any]:
    return {
        "externalId": spec.external_id,
        "name": spec.name,
        "description": spec.description,
        "type": spec.type.value,
        "instructions": spec.instructions,
    }


def to_update_input(spec: SkillSpec, skill_id: str) -> dict[str, Any]:
    return {
        "id": skill_id,
        "name": spec.name,
        "description": spec.description,
        "type": spec.type.value,
        "instructions": spec.instructions,
    }
