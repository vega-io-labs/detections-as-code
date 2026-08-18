"""GraphQL client for the Vega Detection API.

Authenticates via `login_machine` -> JWT, executes detection mutations and
queries, and retries transient transport errors via tenacity. GraphQL-level
errors (TransportQueryError) are user-visible and never retried.
"""

from __future__ import annotations

from typing import Any

import requests
from gql import Client, gql
from gql.transport.exceptions import (
    TransportError,
    TransportQueryError,
    TransportServerError,
)
from gql.transport.requests import RequestsHTTPTransport
from tenacity import (
    retry,
    retry_if_exception,
    stop_after_attempt,
    wait_exponential,
)

DEFAULT_TENANT_URL = "https://app.vega.io"
DEFAULT_PAGE_SIZE = 100
DEFAULT_TIMEOUT_S = 60
MAX_RETRIES = 3
RETRY_BASE_DELAY_S = 1.0
MAX_ERROR_TEXT_CHARS = 500
MAX_PAGES = 1000  # pagination loop safety; >100k detections is implausible


class VegaAPIError(RuntimeError):
    pass


def _retriable(exc: BaseException) -> bool:
    if isinstance(exc, TransportServerError):
        return True
    if isinstance(exc, requests.exceptions.RequestException):
        return True
    # Generic transport hiccup. GraphQL-level errors (TransportQueryError)
    # are user-visible and not retriable.
    return isinstance(exc, TransportError) and not isinstance(
        exc, TransportQueryError
    )


_retry_transient = retry(
    retry=retry_if_exception(_retriable),
    wait=wait_exponential(
        multiplier=RETRY_BASE_DELAY_S, min=RETRY_BASE_DELAY_S, max=10
    ),
    stop=stop_after_attempt(MAX_RETRIES),
    reraise=True,
)


class VegaClient:
    def __init__(
        self,
        tenant_url: str = DEFAULT_TENANT_URL,
        jwt: str | None = None,
        timeout: int = DEFAULT_TIMEOUT_S,
        access_key_id: str | None = None,
        scope_id: str | None = None,
    ) -> None:
        self.tenant_url = tenant_url.rstrip("/")
        self.timeout = timeout
        self._jwt = jwt
        self._access_key_id = access_key_id
        self._scope_id = scope_id
        self._client: Client | None = None
        if jwt:
            self._build_client(jwt)

    @classmethod
    def login(
        cls,
        access_key: str,
        tenant_url: str = DEFAULT_TENANT_URL,
        timeout: int = DEFAULT_TIMEOUT_S,
        access_key_id: str | None = None,
        scope_id: str | None = None,
    ) -> "VegaClient":
        url = f"{tenant_url.rstrip('/')}/api/v1/login_machine"
        # Access keys created on or after 2026-06-18 must assert their key ID
        # on every request via X-Vega-Key-Id; older keys are grandfathered.
        headers = {"X-Vega-Key-Id": access_key_id} if access_key_id else {}
        response = requests.post(
            url,
            json={"access_key": access_key},
            headers=headers,
            timeout=timeout,
        )
        if response.status_code != 200:
            raise RuntimeError(
                f"login_machine failed: {response.status_code} "
                f"{response.text[:MAX_ERROR_TEXT_CHARS]}"
            )
        try:
            body = response.json()
        except ValueError as e:
            raise RuntimeError(
                f"login_machine response was not JSON: {e}; "
                f"body={response.text[:MAX_ERROR_TEXT_CHARS]!r}"
            ) from e
        jwt = body.get("session_jwt")
        if not jwt:
            raise RuntimeError("login_machine response missing session_jwt")
        return cls(
            tenant_url=tenant_url,
            jwt=jwt,
            timeout=timeout,
            access_key_id=access_key_id,
            scope_id=scope_id,
        )

    def _build_client(self, jwt: str) -> None:
        headers = {"Jwtsessiontoken": jwt}
        if self._access_key_id:
            headers["X-Vega-Key-Id"] = self._access_key_id
        # On ABAC-enabled tenants, a key bound to more than one scope must
        # pick one per request or every query is rejected with 403.
        if self._scope_id:
            headers["X-Vega-Scope"] = self._scope_id
        transport = RequestsHTTPTransport(
            url=f"{self.tenant_url}/api/v1/query",
            headers=headers,
            timeout=self.timeout,
            retries=MAX_RETRIES,  # transport-level retry on connection errors
        )
        self._client = Client(
            transport=transport, fetch_schema_from_transport=False
        )
        self._jwt = jwt

    @staticmethod
    @_retry_transient
    def _execute_raw(
        client: Client, query_str: str, variables: dict[str, Any]
    ) -> dict[str, Any]:
        return client.execute(gql(query_str), variable_values=variables)

    def _execute(
        self, query_str: str, variables: dict[str, Any]
    ) -> dict[str, Any]:
        if self._client is None:
            raise RuntimeError(
                "VegaClient not authenticated. Use VegaClient.login(...)."
            )
        try:
            return self._execute_raw(self._client, query_str, variables)
        except TransportQueryError as e:
            raise VegaAPIError(f"GraphQL errors: {e.errors}") from e
        except (TransportError, requests.exceptions.RequestException) as e:
            raise VegaAPIError(
                f"GraphQL request failed: {type(e).__name__}: "
                f"{str(e)[:MAX_ERROR_TEXT_CHARS]}"
            ) from e

    def get_detections(
        self, page_size: int = DEFAULT_PAGE_SIZE
    ) -> list[dict[str, Any]]:
        query = """
        query GetDetections($limit: Int!, $offset: Int!) {
          getDetections(limit: $limit, offset: $offset) {
            detections {
              id
              externalId
              name
              severity
              state
              frequencyCron
              lookBackSeconds
              mitreTactics
              mitreTechniques
              logicDescription
              attackScenario
              references
              deduplicationFields
              deduplicationWindowSeconds
              groupingField
              groupingThreshold
              actorFields
              targetFields
              cells { name query trigger }
            }
            total
            limit
            offset
          }
        }
        """
        all_detections: list[dict[str, Any]] = []
        offset = 0
        for _ in range(MAX_PAGES):
            data = self._execute(query, {"limit": page_size, "offset": offset})
            page = data["getDetections"]
            all_detections.extend(page["detections"])
            offset += len(page["detections"])
            if offset >= page["total"] or not page["detections"]:
                return all_detections
        raise VegaAPIError(
            f"get_detections pagination exceeded {MAX_PAGES} pages "
            f"(over {MAX_PAGES * page_size} detections); something is off"
        )

    def create_detections(
        self, detections: list[dict[str, Any]]
    ) -> dict[str, Any]:
        query = """
        mutation CreateDetections($input: CreateDetectionsInput!) {
          createDetections(input: $input) {
            results {
              name
              status
              errors { message field }
              detection { id externalId }
            }
            summary { requested valid invalid committed }
          }
        }
        """
        return self._execute(query, {"input": {"detections": detections}})[
            "createDetections"
        ]

    def update_detections(
        self, detections: list[dict[str, Any]]
    ) -> dict[str, Any]:
        query = """
        mutation UpdateDetections($input: UpdateDetectionsInput!) {
          updateDetections(input: $input) {
            results {
              name
              status
              errors { message field }
              detection { id externalId }
            }
            summary { requested valid invalid committed }
          }
        }
        """
        return self._execute(query, {"input": {"detections": detections}})[
            "updateDetections"
        ]

    def set_detections_state(
        self, detection_ids: list[str], state: str
    ) -> dict[str, Any]:
        query = """
        mutation SetDetectionsState($input: SetDetectionsStateInput!) {
          setDetectionsState(input: $input) { ids }
        }
        """
        return self._execute(
            query, {"input": {"ids": detection_ids, "state": state}}
        )["setDetectionsState"]

    def delete_detection(self, detection_id: str) -> dict[str, Any]:
        query = """
        mutation DeleteDetection($input: DeleteDetectionInput!) {
          deleteDetection(input: $input) { deletedDetectionId }
        }
        """
        return self._execute(
            query, {"input": {"detectionInstanceId": detection_id}}
        )["deleteDetection"]
