from __future__ import annotations

from typing import Any

YAML_ID = "019e0000-0000-7000-8000-000000000001"


def make_yaml(**overrides: Any) -> dict[str, Any]:
    base: dict[str, Any] = {
        "id": YAML_ID,
        "name": "Root login",
        "severity": 4,
        "state": "enabled",
        "frequencyCron": "5m",
        "lookBackSeconds": 300,
        "query": "@CloudTrail | where event_name == 'ConsoleLogin'",
    }
    base.update(overrides)
    return base


def make_vega(**overrides: Any) -> dict[str, Any]:
    """A detection as getDetections returns it, matching make_yaml() exactly."""
    base: dict[str, Any] = {
        "id": "7d0c7a8e-1c2b-4d3e-9f10-aaaaaaaaaaaa",
        "externalId": YAML_ID,
        "name": "Root login",
        "severity": "CRITICAL",
        "state": "ENABLED",
        "mode": "ALERT",
        "frequencyCron": "@every 5m",
        "lookBackSeconds": 300,
        "mitreTactics": [],
        "mitreTechniques": [],
        "logicDescription": "",
        "attackScenario": "",
        "references": [],
        "deduplicationFields": [],
        "deduplicationWindowSeconds": None,
        "groupingField": None,
        "groupingThreshold": 10,
        "actorFields": [],
        "targetFields": [],
        "skills": [],
        "createdBy": {"principalType": "user"},
        "cells": [
            {
                "name": "trigger",
                "query": "@CloudTrail | where event_name == 'ConsoleLogin'",
                "trigger": True,
            }
        ],
    }
    base.update(overrides)
    return base


MANAGED_LABEL_ID = "11111111-1111-4111-8111-111111111111"
OTHER_LABEL_ID = "22222222-2222-4222-8222-222222222222"
MEMORY_TITLE = "Approved vulnerability scanner"


def make_memory_yaml(**overrides: Any) -> dict[str, Any]:
    base: dict[str, Any] = {
        "title": MEMORY_TITLE,
        "description": "Weekly authenticated scans from scanner-01 are expected.",
        "content": "scanner-01 (192.0.2.10) runs authenticated scans every Sunday 02:00-06:00 UTC.\n",
        "entities": [
            {"type": "device", "value": "scanner-01"},
            {"type": "ip", "value": "192.0.2.10"},
        ],
    }
    base.update(overrides)
    return base


def make_vega_memory(**overrides: Any) -> dict[str, Any]:
    """A memory as getMemories returns it, matching make_memory_yaml() exactly."""
    base: dict[str, Any] = {
        "id": "33333333-3333-4333-8333-333333333333",
        "vegaMemoryId": "MEM-K7QX2",
        "title": MEMORY_TITLE,
        "description": "Weekly authenticated scans from scanner-01 are expected.",
        "content": "scanner-01 (192.0.2.10) runs authenticated scans every Sunday 02:00-06:00 UTC.",
        "status": "ENABLED",
        "enabled": True,
        "expiresAt": None,
        "entities": [
            {"type": "DEVICE", "value": "scanner-01"},
            {"type": "IP", "value": "192.0.2.10"},
        ],
        "labels": [{"id": MANAGED_LABEL_ID, "name": "detections-as-code"}],
    }
    base.update(overrides)
    return base


LABELS = [
    {"id": MANAGED_LABEL_ID, "name": "detections-as-code"},
    {"id": OTHER_LABEL_ID, "name": "Scanners"},
]


SKILL_ID = "8b0f5a3e-2c4d-4e6f-9a1b-3c5d7e9f1a2b"
SKILL_TENANT_ID = "5e6f7a8b-9c0d-5e1f-8a2b-4c6d8e0f2a3b"
SKILL_NAME = "Service account sign-in triage"
SKILL_BODY = (
    "# Triage steps\n\n"
    "Check whether the sign-in came from the service account's fixed egress.\n"
)


def make_skill_md(body: str = SKILL_BODY, **overrides: Any) -> str:
    front: dict[str, Any] = {
        "id": SKILL_ID,
        "name": SKILL_NAME,
        "description": "Sign-ins by service accounts outside their fixed egress.",
        "type": "triage",
    }
    front.update(overrides)
    lines = [f"{k}: {v}" for k, v in front.items() if v is not None]
    return "---\n" + "\n".join(lines) + "\n---\n\n" + body


def make_vega_skill(**overrides: Any) -> dict[str, Any]:
    """A skill as getSkills returns it, matching make_skill_md() exactly."""
    base: dict[str, Any] = {
        "id": SKILL_TENANT_ID,
        "externalId": SKILL_ID,
        "name": SKILL_NAME,
        "description": "Sign-ins by service accounts outside their fixed egress.",
        "type": "TRIAGE",
        "instructions": SKILL_BODY.strip(),
        "readOnly": False,
    }
    base.update(overrides)
    return base
