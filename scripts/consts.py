"""Shared constants for the Vega Detection-as-Code sync engine."""

from __future__ import annotations

from enum import Enum
from typing import Any


class DetectionState(str, Enum):
    ENABLED = "ENABLED"
    DISABLED = "DISABLED"
    TEST_MODE = "TEST_MODE"


DEFAULT_STATE: DetectionState = DetectionState.ENABLED

VALID_STATES: frozenset[str] = frozenset(s.value for s in DetectionState)


class DetectionMode(str, Enum):
    ALERT = "ALERT"
    EVIDENCE = "EVIDENCE"
    MONITOR = "MONITOR"


DEFAULT_MODE: DetectionMode = DetectionMode.ALERT

VALID_MODES: frozenset[str] = frozenset(m.value for m in DetectionMode)

MANDATORY_FIELDS: tuple[str, ...] = (
    "id",
    "name",
    "severity",
    "state",
    "frequencyCron",
    "lookBackSeconds",
)

# Accepts ints (1-4) or case-insensitive strings.
SEVERITY_MAP: dict[Any, str] = {
    1: "LOW",
    2: "MEDIUM",
    3: "HIGH",
    4: "CRITICAL",
    "low": "LOW",
    "medium": "MEDIUM",
    "high": "HIGH",
    "critical": "CRITICAL",
}

# Server-side limits, mirrored here so a violation fails the PR check instead of
# the post-merge sync. createDetections / updateDetections are transactional per
# batch: one rejected detection rolls back every other detection in the same
# call, so catching these early matters more than it looks. Only rules the API
# applies on both the create and the update path belong here - anything
# create-only is a warning instead, since the linter has no tenant access and
# cannot tell which of the two a YAML will become.
NAME_MAX_LEN: int = 200
UNCLEARABLE_TEXT_FIELDS: tuple[str, ...] = ("logicDescription", "attackScenario")
FREQUENCY_INTERVAL_SECONDS_MIN: int = 60
FREQUENCY_INTERVAL_SECONDS_MAX: int = 31 * 24 * 3600
LOOKBACK_SECONDS_MAX: int = FREQUENCY_INTERVAL_SECONDS_MAX
DEDUPLICATION_WINDOW_SECONDS_MAX: int = 24 * 3600
ACTOR_TARGET_FIELDS_MAX: int = 5
SKILL_IDS_MAX: int = 20
GROUPING_THRESHOLD_MIN: int = 2
GROUPING_THRESHOLD_MAX: int = 100

# Keys the public detection API used to accept and no longer does. Neither is
# a straight rename, so the sync refuses them rather than remapping: whichever
# successor it picked would be a guess at intent. The value is the guidance
# shown to the author, not a replacement field name.
#
# `groupingFields` in particular has no single successor. It was dropped as an
# unfinished preparation for deduplication, but the plural has since been
# repurposed as the multi-field form of the burst-protection `groupingField` -
# so "rename it to deduplicationFields" would be wrong advice for anyone who
# meant grouping.
REMOVED_FIELDS: dict[str, str] = {
    "groupingFields": (
        "It has no single successor, so pick by intent: "
        "'deduplicationFields' folds repeat alerts into an open one across "
        "runs, 'groupingField' splits a single noisy run by a field. "
        "Moving over is a behaviour change rather than a rename - "
        "'groupingFields' never affected how alerts were produced, and its "
        "successors do, so check the value still makes sense. "
        "See docs/fields.md"
    ),
    "groupingDurationSeconds": (
        "Use 'deduplicationWindowSeconds' - the same window, under the name "
        "the API now uses. Moving over is a behaviour change rather than a "
        "rename - 'groupingDurationSeconds' never affected how alerts were "
        "produced, and its successor does, so check the value still makes sense"
    ),
    "type": (
        "Use 'mode' - the same setting, under the name the API now uses; "
        "'signal' is now 'evidence'"
    ),
}
