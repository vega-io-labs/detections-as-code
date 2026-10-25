from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest
from graphql import (
    DocumentNode,
    OperationDefinitionNode,
    build_schema,
    validate,
)
from graphql.execution.values import get_variable_values
from gql.transport.exceptions import TransportQueryError

from scripts import client as client_module
from scripts.client import VegaAPIError, VegaClient
from scripts.memory_translator import parse_memory
from scripts.memory_translator import to_create_input as memory_create_input
from scripts.memory_translator import to_update_input as memory_update_input
from scripts.skill_translator import parse_skill
from scripts.skill_translator import to_create_input as skill_create_input
from scripts.skill_translator import to_update_input as skill_update_input
from scripts.translator import yaml_to_create_input, yaml_to_update_input

from .conftest import (
    MANAGED_LABEL_ID,
    make_memory_yaml,
    make_skill_md,
    make_yaml,
)

SCHEMA = build_schema((Path(__file__).parent / "schema.public.graphql").read_text())


class FakeGqlClient:
    def __init__(self, pages: dict[str, list[dict[str, Any]]] | None = None, error: Exception | None = None):
        self.pages = pages or {}
        self.error = error
        self.sent: list[tuple[DocumentNode, dict[str, Any]]] = []

    def execute(self, request: Any, variable_values: dict[str, Any]) -> dict[str, Any]:
        # gql 3 hands over the parsed document, gql 4 a request wrapping it.
        document = getattr(request, "document", request)
        self.sent.append((document, variable_values))
        if self.error is not None:
            raise self.error
        root = _root_field(document)
        if root in self.pages:
            offset, limit = variable_values["offset"], variable_values["limit"]
            items = self.pages[root]
            key = {"getDetections": "detections", "getMemories": "memories", "getSkills": "skills"}[root]
            return {root: {key: items[offset : offset + limit], "total": len(items)}}
        return {root: {"results": [], "summary": {}}}


def _root_field(document: DocumentNode) -> str:
    op = next(d for d in document.definitions if isinstance(d, OperationDefinitionNode))
    return op.selection_set.selections[0].name.value


def _client(gql_client: FakeGqlClient) -> VegaClient:
    client = VegaClient(jwt="jwt")
    client._client = gql_client  # type: ignore[assignment]
    return client


def _call_every_method(client: VegaClient) -> None:
    detection = make_yaml(skillIds=["s1"], mode="evidence")
    memory = parse_memory(make_memory_yaml(expiresAt="2030-01-01", labels=["Scanners"]), "m.yaml")
    skill = parse_skill(make_skill_md(), "skills/a/SKILL.md")

    client.get_detections()
    client.create_detections([yaml_to_create_input(detection)])
    client.update_detections([yaml_to_update_input(detection)])
    client.set_detections_state(["d1"], "TEST_MODE")
    client.delete_detection("d1")
    client.get_memories()
    client.create_memory(memory_create_input(memory, [MANAGED_LABEL_ID]))
    client.update_memory(memory_update_input(memory, "m1", [MANAGED_LABEL_ID]))
    client.update_memory(memory_update_input(parse_memory(make_memory_yaml(), "m.yaml"), "m1", []))
    client.delete_memory("m1")
    client.list_labels()
    client.create_label("detections-as-code", "TEAL")
    client.get_skills()
    client.create_skills([skill_create_input(skill)])
    client.update_skills([skill_update_input(skill, "s1")])
    client.delete_skills(["s1"])


def test_every_document_and_payload_matches_the_public_schema():
    gql_client = FakeGqlClient(pages={"getDetections": [], "getMemories": [], "getSkills": []})
    _call_every_method(_client(gql_client))

    assert len(gql_client.sent) == 16
    for document, variables in gql_client.sent:
        root = _root_field(document)
        assert validate(SCHEMA, document) == [], root
        op = next(d for d in document.definitions if isinstance(d, OperationDefinitionNode))
        coerced = get_variable_values(SCHEMA, op.variable_definitions or [], variables)
        # A list is the coercion errors; success is a mapping of the values.
        assert not isinstance(coerced, list), (root, [str(e) for e in coerced])


@pytest.mark.parametrize(
    "method,root,page_size",
    [
        ("get_detections", "getDetections", client_module.DETECTION_PAGE_SIZE),
        ("get_memories", "getMemories", client_module.MEMORY_PAGE_SIZE),
        ("get_skills", "getSkills", client_module.SKILL_PAGE_SIZE),
    ],
)
def test_pagination_reads_every_page(method, root, page_size):
    items = [{"id": str(i)} for i in range(page_size * 2 + 7)]
    gql_client = FakeGqlClient(pages={root: items})
    assert getattr(_client(gql_client), method)() == items
    assert [v["offset"] for _, v in gql_client.sent] == [0, page_size, page_size * 2]
    assert {v["limit"] for _, v in gql_client.sent} == {page_size}


def test_memories_are_read_newest_first():
    gql_client = FakeGqlClient(pages={"getMemories": []})
    _client(gql_client).get_memories()
    assert gql_client.sent[0][1]["sortBy"] == "UPDATED_AT"
    assert gql_client.sent[0][1]["sortOrder"] == "DESC"


def test_pagination_stops_after_max_pages(monkeypatch):
    class Endless(FakeGqlClient):
        def execute(self, request, variable_values):
            self.sent.append((request, variable_values))
            return {"getSkills": {"skills": [{"id": "x"}], "total": 10**9}}

    monkeypatch.setattr(client_module, "MAX_PAGES", 3)
    gql_client = Endless()
    with pytest.raises(VegaAPIError, match="exceeded 3 pages"):
        _client(gql_client).get_skills()
    assert len(gql_client.sent) == 3


def test_graphql_errors_expose_their_codes():
    errors = [
        {"message": "denied", "extensions": {"error_code_name": "ACCESS_DENIED"}},
        {"message": "no code"},
        "not a dict",
    ]
    gql_client = FakeGqlClient(error=TransportQueryError("boom", errors=errors))
    with pytest.raises(VegaAPIError) as raised:
        _client(gql_client).list_labels()
    assert raised.value.codes == frozenset({"ACCESS_DENIED"})


def test_a_message_that_mentions_a_code_carries_no_code():
    assert VegaAPIError("GraphQL errors: ACCESS_DENIED in a title").codes == frozenset()


@pytest.mark.parametrize(
    "call,permission",
    [
        (lambda c: c.create_label("detections-as-code", "TEAL"), "LabelsWrite"),
        (lambda c: c.create_skills([]), "AgentsWrite"),
        (lambda c: c.get_memories(), "AgentsRead"),
    ],
)
def test_access_denied_names_the_permission_the_call_needs(call, permission):
    denied = [{"extensions": {"error_code_name": "ACCESS_DENIED"}}]
    gql_client = FakeGqlClient(error=TransportQueryError("boom", errors=denied))
    with pytest.raises(VegaAPIError, match=f"needs the {permission} permission"):
        call(_client(gql_client))


def test_known_error_codes_carry_a_hint():
    limit = [{"extensions": {"error_code_name": "MEMORY_LIMIT_REACHED"}}]
    assert "learned by Vega" in str(VegaAPIError("GraphQL errors", limit))
    assert "permission" not in str(VegaAPIError("GraphQL errors", limit, "AgentsWrite"))
