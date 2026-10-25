"""The plan and report shapes shared by the detection, skill and memory sync."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Generic, Literal, TypeVar

P = TypeVar("P")

ActionKind = Literal["create", "update", "delete", "set_state"]
Target = Literal["detection", "memory", "skill"]


@dataclass(frozen=True)
class Planned(Generic[P]):
    external_id: str
    name: str
    payload: P


Write = Planned[dict[str, Any]]
Delete = Planned[str]


@dataclass(frozen=True)
class Blocked:
    kind: ActionKind
    external_id: str
    name: str
    reason: str


@dataclass
class Plan:
    creates: list[Write] = field(default_factory=list)
    updates: list[Write] = field(default_factory=list)
    deletes: list[Delete] = field(default_factory=list)
    blocked: list[Blocked] = field(default_factory=list)
    no_op_updates: int = 0

    def summary(self) -> str:
        return (
            f"creates={len(self.creates)} "
            f"updates={len(self.updates)} "
            f"deletes={len(self.deletes)} "
            f"blocked={len(self.blocked)} "
            f"no_op_skipped={self.no_op_updates}"
        )


@dataclass
class ActionResult:
    kind: ActionKind
    external_id: str
    name: str
    success: bool
    error: str | None = None
    target: Target = "detection"


@dataclass
class SyncReport:
    results: list[ActionResult] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)

    def add(self, r: ActionResult) -> None:
        self.results.append(r)

    def add_blocked(self, plan: Plan, target: Target) -> None:
        for b in plan.blocked:
            self.add(
                ActionResult(
                    b.kind, b.external_id, b.name, False, b.reason, target=target
                )
            )

    @property
    def succeeded(self) -> list[ActionResult]:
        return [r for r in self.results if r.success]

    @property
    def failed(self) -> list[ActionResult]:
        return [r for r in self.results if not r.success]

    @property
    def all_ok(self) -> bool:
        return not self.failed and not self.errors
