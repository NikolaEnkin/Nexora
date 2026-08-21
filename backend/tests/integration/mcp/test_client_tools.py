"""`P04-004` and the client tool lifecycle.

`ARCH-004` is the claim under test: an accepted mutation commits the client row,
its domain event, the outbox entry, the idempotency result and the audit record
**together**, exactly once, even under concurrency.
"""

from concurrent.futures import ThreadPoolExecutor
from uuid import UUID, uuid4

import pytest

from app.mcp.contracts import ToolAudience, ToolOutcome
from tests.integration.mcp.support import (
    approve_pending,
    build_mcp_harness,
    counts,
    envelope,
    operator,
)

pytestmark = pytest.mark.integration


def _create(harness, actor, key="create-1", name="Example GmbH"):  # type: ignore[no-untyped-def]
    call = envelope(
        "client_create",
        {"legal_name": name, "display_name": name.split()[0]},
        idempotency_key=key,
    )
    approve_pending(harness, actor, call)
    return call


def test_an_approved_create_writes_every_row_exactly_once() -> None:
    harness = build_mcp_harness()
    actor = operator(1)
    call = _create(harness, actor)

    result = harness.gateway.call(
        actor=actor, envelope=call, authenticated_audience=ToolAudience.AGENT
    )

    assert result.outcome is ToolOutcome.SUCCEEDED
    assert result.replayed is False
    assert result.resource is not None
    assert result.resource["legal_name"] == "Example GmbH"
    assert result.resource["normalized_key"] == "example gmbh"
    assert result.resource_version == 1
    assert counts(harness, actor) == {
        "clients": 1,
        "domain_events": 1,
        "outbox_events": 1,
        "audit_events": 1,
    }


def test_ten_identical_calls_produce_one_client() -> None:
    """`P04-004` — ten concurrent workers, one client, one of every record."""
    workers = 10
    harness = build_mcp_harness(pool_size=workers + 2)
    actor = operator(1)
    call = _create(harness, actor, key="concurrent-1")

    def attempt(_index: int) -> str:
        return harness.gateway.call(
            actor=actor, envelope=call, authenticated_audience=ToolAudience.AGENT
        ).outcome.value

    with ThreadPoolExecutor(max_workers=workers) as pool:
        outcomes = list(pool.map(attempt, range(workers)))

    assert all(outcome == ToolOutcome.SUCCEEDED.value for outcome in outcomes), outcomes
    assert counts(harness, actor) == {
        "clients": 1,
        "domain_events": 1,
        "outbox_events": 1,
        "audit_events": 1,
    }


def test_a_repeat_after_success_reports_a_replay() -> None:
    """The caller must be able to tell a fresh write from a durable replay."""
    harness = build_mcp_harness()
    actor = operator(1)
    call = _create(harness, actor, key="replay-1")

    first = harness.gateway.call(
        actor=actor, envelope=call, authenticated_audience=ToolAudience.AGENT
    )
    second = harness.gateway.call(
        actor=actor, envelope=call, authenticated_audience=ToolAudience.AGENT
    )

    assert first.replayed is False
    assert second.replayed is True
    assert second.resource == first.resource
    assert counts(harness, actor)["clients"] == 1


def test_a_client_can_be_read_back_by_id_and_by_exact_name() -> None:
    harness = build_mcp_harness()
    actor = operator(1)
    call = _create(harness, actor, key="read-back")
    created = harness.gateway.call(
        actor=actor, envelope=call, authenticated_audience=ToolAudience.AGENT
    )
    assert created.resource is not None
    client_id = created.resource["client_id"]

    by_id = harness.gateway.call(
        actor=actor,
        envelope=envelope("client_get", {"client_id": client_id}),
        authenticated_audience=ToolAudience.AGENT,
    )
    # Case and spacing fold to the same canonical identity.
    by_name = harness.gateway.call(
        actor=actor,
        envelope=envelope("client_get", {"legal_name": "  EXAMPLE   gmbh "}),
        authenticated_audience=ToolAudience.AGENT,
    )

    assert by_id.outcome is ToolOutcome.SUCCEEDED
    assert by_name.outcome is ToolOutcome.SUCCEEDED
    assert by_id.resource == by_name.resource


def test_two_clients_cannot_share_one_active_identity() -> None:
    """The partial unique index is what stops an invoice going to the wrong twin."""
    harness = build_mcp_harness()
    actor = operator(1)
    first = _create(harness, actor, key="identity-1")
    harness.gateway.call(actor=actor, envelope=first, authenticated_audience=ToolAudience.AGENT)

    duplicate = _create(harness, actor, key="identity-2", name="EXAMPLE  GmbH")
    result = harness.gateway.call(
        actor=actor, envelope=duplicate, authenticated_audience=ToolAudience.AGENT
    )

    assert result.outcome is ToolOutcome.FAILED
    assert result.error is not None
    assert result.error.code == "BUSINESS_RULE_VIOLATION"
    assert counts(harness, actor)["clients"] == 1


def test_an_update_increments_the_version_and_needs_the_one_it_saw() -> None:
    """`BR-04-004` — optimistic concurrency, and the backend owns the version."""
    harness = build_mcp_harness()
    actor = operator(1)
    call = _create(harness, actor, key="update-base")
    created = harness.gateway.call(
        actor=actor, envelope=call, authenticated_audience=ToolAudience.AGENT
    )
    assert created.resource is not None
    client_id = created.resource["client_id"]

    patch = envelope(
        "client_update",
        {"client_id": client_id, "expected_version": 1, "display_name": "Example AG"},
        idempotency_key="update-1",
    )
    approve_pending(harness, actor, patch)
    updated = harness.gateway.call(
        actor=actor, envelope=patch, authenticated_audience=ToolAudience.AGENT
    )

    assert updated.outcome is ToolOutcome.SUCCEEDED
    assert updated.resource is not None
    assert updated.resource["display_name"] == "Example AG"
    assert updated.resource_version == 2

    stale = envelope(
        "client_update",
        {"client_id": client_id, "expected_version": 1, "display_name": "Too Late"},
        idempotency_key="update-stale",
    )
    approve_pending(harness, actor, stale)
    conflict = harness.gateway.call(
        actor=actor, envelope=stale, authenticated_audience=ToolAudience.AGENT
    )
    assert conflict.outcome is ToolOutcome.FAILED
    assert conflict.error is not None
    assert conflict.error.code == "VERSION_CONFLICT"


def test_archiving_frees_the_identity_for_reuse() -> None:
    """The unique index is partial on ACTIVE, so a closed client does not block a new one."""
    harness = build_mcp_harness()
    actor = operator(1)
    call = _create(harness, actor, key="archive-base")
    created = harness.gateway.call(
        actor=actor, envelope=call, authenticated_audience=ToolAudience.AGENT
    )
    assert created.resource is not None

    archive = envelope(
        "client_update",
        {
            "client_id": created.resource["client_id"],
            "expected_version": 1,
            "status": "ARCHIVED",
        },
        idempotency_key="archive-1",
    )
    approve_pending(harness, actor, archive)
    archived = harness.gateway.call(
        actor=actor, envelope=archive, authenticated_audience=ToolAudience.AGENT
    )
    assert archived.outcome is ToolOutcome.SUCCEEDED
    assert archived.resource is not None
    assert archived.resource["status"] == "ARCHIVED"

    again = _create(harness, actor, key="archive-reuse")
    reused = harness.gateway.call(
        actor=actor, envelope=again, authenticated_audience=ToolAudience.AGENT
    )
    assert reused.outcome is ToolOutcome.SUCCEEDED
    assert counts(harness, actor)["clients"] == 2


def test_the_backend_owns_the_identity_not_the_caller() -> None:
    """`BR-04-003` — there is no field through which a caller supplies an id."""
    from app.mcp.registry import CLIENT_CREATE

    assert "client_id" not in CLIENT_CREATE.input_schema["properties"]
    assert "row_version" not in CLIENT_CREATE.input_schema["properties"]
    assert "normalized_key" not in CLIENT_CREATE.input_schema["properties"]
    assert UUID is not None and uuid4() is not None
