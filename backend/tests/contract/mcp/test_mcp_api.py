"""The tool boundary over HTTP.

The point of these cases is that everything the in-process gateway refuses is
still refused when the same attempt arrives as an HTTP request — and that the
transport adds no new way in.
"""

from uuid import uuid4

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from app.api.mcp import McpApiDependencies
from app.api.mcp import router as mcp_router
from app.errors import install_error_handlers
from app.mcp.contracts import ToolOutcome
from tests.integration.mcp.support import build_mcp_harness, operator, owner, viewer

pytestmark = pytest.mark.contract


def _client(harness, actor):  # type: ignore[no-untyped-def]
    app = FastAPI()
    install_error_handlers(app)
    app.state.mcp = McpApiDependencies(gateway=harness.gateway)
    app.include_router(mcp_router)

    @app.middleware("http")
    async def attach_actor(request, call_next):  # type: ignore[no-untyped-def]
        if actor is not None:
            request.state.actor = actor
        return await call_next(request)

    return TestClient(app, raise_server_exceptions=False)


def test_discovery_lists_exactly_the_client_tools() -> None:
    harness = build_mcp_harness()
    response = _client(harness, operator(1)).get("/mcp/tools")

    assert response.status_code == 200
    body = response.json()
    assert body["audience"] == "operator_ui"
    names = {tool["name"] for tool in body["tools"]}
    assert names == {"client_get", "client_create", "client_update"}


def test_discovery_shows_the_risk_from_the_accepted_catalogue() -> None:
    """An operator can see what a call will cost before making it."""
    harness = build_mcp_harness()
    body = _client(harness, operator(1)).get("/mcp/tools").json()
    by_name = {tool["name"]: tool for tool in body["tools"]}

    assert by_name["client_get"]["risk"] == "R1"
    assert by_name["client_create"]["risk"] == "R2"
    assert by_name["client_create"]["required_permission"] == "client.write"
    assert by_name["client_create"]["requires_idempotency_key"] is True
    assert by_name["client_get"]["input_schema"]["additionalProperties"] is False


def test_the_endpoint_needs_a_session() -> None:
    harness = build_mcp_harness()
    client = _client(harness, None)

    assert client.get("/mcp/tools").status_code == 401
    assert client.post("/mcp/call", json={"tool_name": "client_get"}).status_code == 401


def test_the_body_cannot_choose_an_audience_or_an_identity() -> None:
    """`extra="forbid"`, and the audience is derived server-side regardless."""
    harness = build_mcp_harness()
    client = _client(harness, operator(1))

    for smuggled in (
        {"audience": "agent"},
        {"actor_id": str(uuid4())},
        {"tenant_id": str(uuid4())},
        {"roles": ["OWNER"]},
    ):
        response = client.post(
            "/mcp/call",
            json={"tool_name": "client_get", "arguments": {}, **smuggled},
        )
        assert response.status_code == 422, smuggled


def test_a_generic_tool_over_http_is_unavailable() -> None:
    harness = build_mcp_harness()
    client = _client(harness, operator(1))

    for name in ("sql_query", "shell", "http_request", "client_delete"):
        response = client.post("/mcp/call", json={"tool_name": name, "arguments": {}})
        assert response.status_code == 403
        assert response.json()["code"] == "TOOL_NOT_ALLOWED"


def test_a_protected_write_returns_approval_required_as_a_result() -> None:
    """`200` with an outcome, not a transport error: the caller needs the id."""
    harness = build_mcp_harness()
    client = _client(harness, operator(1))

    response = client.post(
        "/mcp/call",
        json={
            "tool_name": "client_create",
            "arguments": {"legal_name": "Example GmbH", "display_name": "Example"},
            "idempotency_key": "http-create-1",
        },
    )

    assert response.status_code == 200
    body = response.json()
    assert body["outcome"] == ToolOutcome.APPROVAL_REQUIRED.value
    assert "approval_id" in body["error"]["details"]
    assert body["resource"] is None


def test_an_unauthorized_actor_is_denied_as_a_result() -> None:
    harness = build_mcp_harness()
    response = _client(harness, viewer()).post(
        "/mcp/call",
        json={
            "tool_name": "client_create",
            "arguments": {"legal_name": "Example GmbH", "display_name": "Example"},
            "idempotency_key": "http-denied-1",
        },
    )

    assert response.status_code == 200
    assert response.json()["outcome"] == ToolOutcome.DENIED.value


def test_an_approved_write_succeeds_over_http() -> None:
    """The whole path: discover, call, get refused, approve, call again."""
    from uuid import UUID

    from app.approvals.contracts import DecisionType

    harness = build_mcp_harness()
    actor = operator(1)
    client = _client(harness, actor)
    payload = {
        "tool_name": "client_create",
        "arguments": {"legal_name": "Example GmbH", "display_name": "Example"},
        "idempotency_key": "http-approved-1",
    }

    opened = client.post("/mcp/call", json=payload).json()
    approval_id = UUID(opened["error"]["details"]["approval_id"])
    request = harness.approvals.repository.load(actor=actor, approval_id=approval_id)
    assert request is not None
    harness.approvals.service.decide(
        actor=owner(),
        approval_id=approval_id,
        decision=DecisionType.APPROVED,
        payload_hash=request.payload_hash,
        idempotency_key="http-decide-1",
    )

    executed = client.post("/mcp/call", json=payload).json()

    assert executed["outcome"] == ToolOutcome.SUCCEEDED.value
    assert executed["resource"]["legal_name"] == "Example GmbH"
    assert executed["resource_version"] == 1
    assert executed["replayed"] is False

    replayed = client.post("/mcp/call", json=payload).json()
    assert replayed["outcome"] == ToolOutcome.SUCCEEDED.value
    assert replayed["replayed"] is True
