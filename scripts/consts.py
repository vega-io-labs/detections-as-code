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

DEFAULT_TYPE: str = "ALERT"

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
