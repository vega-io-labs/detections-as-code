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
