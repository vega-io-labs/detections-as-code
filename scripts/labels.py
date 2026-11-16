"""Label names in files and the tenant labels they resolve to.

Label names are unique per tenant ignoring case, so every name is compared
through label_key, both in a file and against the tenant.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from .consts import MANAGED_LABEL, MANAGED_LABEL_COLOR

if TYPE_CHECKING:
    from .client import VegaClient


def label_key(name: str) -> str:
    return name.strip().lower()


def label_ids_by_name(labels: list[dict[str, Any]]) -> dict[str, str]:
    return {label_key(label.get("name") or ""): label["id"] for label in labels}


def is_managed_label(name: str) -> bool:
    return label_key(name) == label_key(MANAGED_LABEL)


def managed_label_id(labels: list[dict[str, Any]]) -> str | None:
    return label_ids_by_name(labels).get(label_key(MANAGED_LABEL))


class ManagedLabel:
    def __init__(self, client: "VegaClient") -> None:
        self._client = client
        self._id: str | None = None

    def id(self) -> str:
        if self._id is None:
            existing = managed_label_id(self._client.list_labels())
            self._id = existing or self._client.create_label(
                MANAGED_LABEL, MANAGED_LABEL_COLOR
            )["id"]
        return self._id


def parse_label_names(value: Any, where: str) -> tuple[str, ...]:
    if value is None:
        return ()
    if not isinstance(value, list):
        raise ValueError(f"{where}: 'labels' must be a list of label names")
    names: list[str] = []
    seen: set[str] = set()
    for i, name in enumerate(value):
        if not isinstance(name, str) or not name.strip():
            raise ValueError(f"{where}: labels[{i}] must be a non-empty label name")
        name = name.strip()
        if is_managed_label(name):
            raise ValueError(
                f"{where}: labels[{i}] {name!r} is added by the sync to every "
                f"memory it manages; leave it out"
            )
        if label_key(name) in seen:
            raise ValueError(f"{where}: labels[{i}] {name!r} is duplicated")
        seen.add(label_key(name))
        names.append(name)
    return tuple(names)
