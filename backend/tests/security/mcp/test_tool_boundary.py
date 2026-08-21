"""`P04-002` and `P04-003` — nothing reaches a business service without passing
audience, schema, authorization and policy, in that order.

Every negative asserts durable row counts, not just an error code. An error with a
row written behind it is the failure mode these tests exist to catch.
"""

from uuid import uuid4

import pytest

from app.approvals.errors import ApprovalRequired
from app.contracts import ActorContext
from app.mcp.contracts import ToolAudience, ToolOutcome
from app.mcp.gateway import ToolNotAllowed, ToolSchemaInvalid
from tests.integration.foundation.support import TENANT_A
from tests.integration.mcp.support import (
    build_mcp_harness,
    counts,
    envelope,
    operator,
    viewer,
)

pytestmark = pytest.mark.security


def test_a_generic_or_unknown_tool_is_unavailable() -> None:
    """`P04-002` — the names an attacker would try, and the names nobody declared."""
    harness = build_mcp_harness()
    actor = operator(1)
    before = counts(harness, actor)

    for name in (
        "sql_query",
        "execute_sql",
        "shell",
        "bash",
        "http_request",
        "fetch",
        "cypher",
        "read_file",
        "write_file",
        "admin",
        "client_delete",
        "eval",
    ):
        with pytest.raises(ToolNotAllowed):
            harness.gateway.call(
                actor=actor,
                envelope=envelope(name, {"anything": "goes"}),
                authenticated_audience=ToolAudience.AGENT,
            )

    assert counts(harness, actor) == before


def test_a_forged_audience_selects_nothing() -> None:
    """`P04-002` — the claimed audience must match the authenticated one."""
    harness = build_mcp_harness()
    actor = operator(1)
    before = counts(harness, actor)

    with pytest.raises(ToolNotAllowed):
        harness.gateway.call(
            actor=actor,
            envelope=envelope(
                "client_get", {"client_id": str(uuid4())}, audience=ToolAudience.OPERATOR_UI
            ),
            authenticated_audience=ToolAudience.AGENT,
        )

    assert counts(harness, actor) == before


def test_an_undeclared_argument_is_refused_before_the_service() -> None:
    """The closed schema is the control; this proves it is actually applied."""
    harness = build_mcp_harness()
    actor = operator(1)
    before = counts(harness, actor)

    for smuggled in (
        {"legal_name": "X", "display_name": "X", "sql": "DROP TABLE clients"},
        {"legal_name": "X", "display_name": "X", "tenant_id": str(uuid4())},
        {"legal_name": "X", "display_name": "X", "row_version": 99},
        {"legal_name": "X", "display_name": "X", "approved": True},
    ):
        with pytest.raises(ToolSchemaInvalid):
            harness.gateway.call(
                actor=actor,
                envelope=envelope("client_create", smuggled, idempotency_key="smuggle"),
                authenticated_audience=ToolAudience.AGENT,
            )

    assert counts(harness, actor) == before


def test_a_write_without_an_idempotency_key_is_refused() -> None:
    harness = build_mcp_harness()
    actor = operator(1)
    before = counts(harness, actor)

    with pytest.raises(ToolSchemaInvalid):
        harness.gateway.call(
            actor=actor,
            envelope=envelope("client_create", {"legal_name": "X", "display_name": "X"}),
            authenticated_audience=ToolAudience.AGENT,
        )

    assert counts(harness, actor) == before


def test_an_unauthorized_actor_writes_nothing() -> None:
    """`P04-003` — a VIEWER holds no `client.write`, so policy never opens."""
    harness = build_mcp_harness()
    before = counts(harness, viewer())

    result = harness.gateway.call(
        actor=viewer(),
        envelope=envelope(
            "client_create",
            {"legal_name": "Example GmbH", "display_name": "Example"},
            idempotency_key="viewer-attempt",
        ),
        authenticated_audience=ToolAudience.AGENT,
    )

    assert result.outcome is ToolOutcome.DENIED
    assert result.error is not None
    assert result.error.code == "AUTHORIZATION_DENIED"
    assert counts(harness, viewer()) == before


def test_a_foreign_tenant_actor_reads_nothing() -> None:
    """`P04-003` — row-level security is the boundary, even with a real id."""
    harness = build_mcp_harness()
    actor = operator(1)
    call = envelope(
        "client_create",
        {"legal_name": "Example GmbH", "display_name": "Example"},
        idempotency_key="tenant-isolation",
    )
    from tests.integration.mcp.support import approve_pending

    approve_pending(harness, actor, call)
    created = harness.gateway.call(
        actor=actor, envelope=call, authenticated_audience=ToolAudience.AGENT
    )
    assert created.outcome is ToolOutcome.SUCCEEDED
    assert created.resource is not None
    client_id = created.resource["client_id"]

    intruder = ActorContext(
        tenant_id=uuid4(),
        actor_id=uuid4(),
        subject="auth0|intruder",
        auth_method="test_fixture",
        roles=("OPERATOR",),
        permissions=("client.read", "client.write"),
        correlation_id=uuid4(),
    )
    result = harness.gateway.call(
        actor=intruder,
        envelope=envelope("client_get", {"client_id": client_id}),
        authenticated_audience=ToolAudience.AGENT,
    )
    assert result.outcome is ToolOutcome.FAILED
    assert result.error is not None
    # Indistinguishable from an id that never existed.
    assert result.error.code == "CLIENT_NOT_FOUND"
    assert result.error.details == {}


def test_a_protected_write_requires_a_human_decision_first() -> None:
    """`client_create` is R2 under `ADR-004`, so the first call opens an approval."""
    harness = build_mcp_harness()
    actor = operator(1)
    before = counts(harness, actor)

    result = harness.gateway.call(
        actor=actor,
        envelope=envelope(
            "client_create",
            {"legal_name": "Example GmbH", "display_name": "Example"},
            idempotency_key="needs-approval",
        ),
        authenticated_audience=ToolAudience.AGENT,
    )

    assert result.outcome is ToolOutcome.APPROVAL_REQUIRED
    assert result.error is not None
    assert "approval_id" in result.error.details
    # Nothing durable in the business domain yet.
    assert counts(harness, actor) == before


def test_a_read_needs_no_approval() -> None:
    """`client_get` is R1: authorization is enough, and it writes nothing."""
    harness = build_mcp_harness()
    actor = operator(1)
    before = counts(harness, actor)

    result = harness.gateway.call(
        actor=actor,
        envelope=envelope("client_get", {"client_id": str(uuid4())}),
        authenticated_audience=ToolAudience.AGENT,
    )

    assert result.outcome is ToolOutcome.FAILED
    assert result.error is not None
    assert result.error.code == "CLIENT_NOT_FOUND"
    assert counts(harness, actor) == before


def test_resolution_never_guesses_between_two_references() -> None:
    """`BR-04-001` — neither reference, or both, is a refusal rather than a guess."""
    harness = build_mcp_harness()
    actor = operator(1)

    for arguments in ({}, {"client_id": str(uuid4()), "legal_name": "Example GmbH"}):
        result = harness.gateway.call(
            actor=actor,
            envelope=envelope("client_get", arguments),
            authenticated_audience=ToolAudience.AGENT,
        )
        assert result.outcome is ToolOutcome.FAILED
        assert result.error is not None
        assert result.error.code == "BUSINESS_RULE_VIOLATION"


def test_the_approval_is_bound_to_the_exact_payload() -> None:
    """`ARCH-007` through the tool layer: change a name, lose the approval."""
    from tests.integration.mcp.support import approve_pending

    harness = build_mcp_harness()
    actor = operator(1)
    original = envelope(
        "client_create",
        {"legal_name": "Example GmbH", "display_name": "Example"},
        idempotency_key="binding",
    )
    approve_pending(harness, actor, original)

    edited = envelope(
        "client_create",
        {"legal_name": "Different GmbH", "display_name": "Example"},
        idempotency_key="binding",
    )
    result = harness.gateway.call(
        actor=actor, envelope=edited, authenticated_audience=ToolAudience.AGENT
    )
    assert result.outcome is ToolOutcome.FAILED
    assert result.error is not None
    assert result.error.code == "APPROVAL_STALE"
    assert counts(harness, actor)["clients"] == 0


def test_approval_required_is_an_outcome_not_an_exception_at_the_boundary() -> None:
    """The caller must be able to act on it, so it is a ToolResult, not a 500."""
    harness = build_mcp_harness()
    actor = operator(1)
    result = harness.gateway.call(
        actor=actor,
        envelope=envelope(
            "client_create",
            {"legal_name": "Example GmbH", "display_name": "Example"},
            idempotency_key="outcome-shape",
        ),
        authenticated_audience=ToolAudience.AGENT,
    )
    assert isinstance(result.outcome, ToolOutcome)
    assert result.resource is None
    assert not isinstance(result, ApprovalRequired)
    assert TENANT_A is not None
