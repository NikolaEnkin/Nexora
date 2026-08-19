"""Idempotent operation creation and tenant/actor ownership.

Covers `BR-02-001` (one operation per request identity) and `BR-02-002` (loading
requires tenant and actor ownership). LangGraph is deliberately not involved: this
slice proves the durable identity that later slices resume onto.
"""

from concurrent.futures import ThreadPoolExecutor
from uuid import UUID

import pytest
from backend.tests.integration.agent.support import (
    ACTOR_A,
    ACTOR_B,
    FIXED_NOW,
    TENANT_A,
    TENANT_B,
    actor_for,
    count_all,
    migration_engine,
    reset_agent_data,
    runtime_sessions,
    seed_both_tenants,
)
from sqlalchemy import text

from app.agent.errors import InvalidState, OperationNotFound
from app.agent.identity import derive_operation_id
from app.agent.operations import OperationRepository
from app.agent.state import AgentRoute, OperationState
from app.db import set_request_context

CONCURRENT_WORKERS = 10


@pytest.fixture
def repository() -> OperationRepository:
    admin = migration_engine()
    seed_both_tenants(admin)
    reset_agent_data(admin)
    return OperationRepository(sessions=runtime_sessions(pool_size=CONCURRENT_WORKERS + 2))


def _count_operations() -> int:
    """Global count through the BYPASSRLS guard role, so "exactly one" is provable."""
    return count_all(migration_engine(), "agent_operations")


@pytest.mark.integration
def test_first_request_creates_exactly_one_operation(repository: OperationRepository) -> None:
    actor = actor_for(TENANT_A, ACTOR_A)

    result = repository.create_or_restore(
        actor=actor, client_request_id="req-001", conversation_id=None, now=FIXED_NOW
    )

    assert result.created is True
    assert result.operation.state is OperationState.RECEIVED
    assert result.operation.tenant_id == TENANT_A
    assert result.operation.actor_id == ACTOR_A
    assert result.operation.checkpoint_seq == 0
    assert result.operation.route is None
    assert result.operation.error_code is None
    assert result.operation.operation_id == derive_operation_id(TENANT_A, ACTOR_A, "req-001")
    assert len(result.operation.thread_id) == 32
    # The thread key is opaque, never a display name.
    assert "req-001" not in result.operation.thread_id
    assert _count_operations() == 1


@pytest.mark.integration
def test_exact_retry_returns_the_same_operation(repository: OperationRepository) -> None:
    actor = actor_for(TENANT_A, ACTOR_A)

    first = repository.create_or_restore(
        actor=actor, client_request_id="req-002", conversation_id=None, now=FIXED_NOW
    )
    repository.transition(
        actor=actor,
        operation_id=first.operation.operation_id,
        target=OperationState.RUNNING,
        now=FIXED_NOW,
        route=AgentRoute.ECHO,
    )

    retry = repository.create_or_restore(
        actor=actor, client_request_id="req-002", conversation_id=None, now=FIXED_NOW
    )

    assert retry.created is False
    assert retry.operation.operation_id == first.operation.operation_id
    # A retry restores; it never resets progress already made.
    assert retry.operation.state is OperationState.RUNNING
    assert retry.operation.route is AgentRoute.ECHO
    assert _count_operations() == 1


@pytest.mark.integration
def test_ten_concurrent_identical_starts_produce_one_operation(
    repository: OperationRepository,
) -> None:
    actor = actor_for(TENANT_A, ACTOR_A)

    def start() -> UUID:
        return repository.create_or_restore(
            actor=actor, client_request_id="req-concurrent", conversation_id=None, now=FIXED_NOW
        ).operation.operation_id

    with ThreadPoolExecutor(max_workers=CONCURRENT_WORKERS) as pool:
        results = [
            future.result() for future in [pool.submit(start) for _ in range(CONCURRENT_WORKERS)]
        ]

    assert len(results) == CONCURRENT_WORKERS
    assert len(set(results)) == 1
    assert results[0] == derive_operation_id(TENANT_A, ACTOR_A, "req-concurrent")
    assert _count_operations() == 1


@pytest.mark.integration
def test_another_actor_and_another_tenant_cannot_load_it(
    repository: OperationRepository,
) -> None:
    owner = actor_for(TENANT_A, ACTOR_A)
    created = repository.create_or_restore(
        actor=owner, client_request_id="req-owned", conversation_id=None, now=FIXED_NOW
    )
    operation_id = created.operation.operation_id

    # Same tenant, different actor.
    foreign_actor = actor_for(TENANT_A, ACTOR_B)
    with pytest.raises(OperationNotFound):
        repository.load(actor=foreign_actor, operation_id=operation_id)

    # Different tenant entirely.
    other_tenant = actor_for(TENANT_B, ACTOR_B)
    with pytest.raises(OperationNotFound):
        repository.load(actor=other_tenant, operation_id=operation_id)

    # A guessed identifier is indistinguishable from a foreign one.
    with pytest.raises(OperationNotFound):
        repository.load(
            actor=other_tenant, operation_id=UUID("ffffffff-ffff-4fff-8fff-ffffffffffff")
        )

    # The owner still sees it, unchanged.
    assert repository.load(actor=owner, operation_id=operation_id) == created.operation
    assert _count_operations() == 1


@pytest.mark.integration
def test_same_client_request_id_under_a_different_tenant_is_a_different_operation(
    repository: OperationRepository,
) -> None:
    a = repository.create_or_restore(
        actor=actor_for(TENANT_A, ACTOR_A),
        client_request_id="shared-id",
        conversation_id=None,
        now=FIXED_NOW,
    )
    b = repository.create_or_restore(
        actor=actor_for(TENANT_B, ACTOR_B),
        client_request_id="shared-id",
        conversation_id=None,
        now=FIXED_NOW,
    )

    assert a.created is True
    assert b.created is True
    assert a.operation.operation_id != b.operation.operation_id
    assert a.operation.thread_id != b.operation.thread_id
    assert _count_operations() == 2


@pytest.mark.integration
def test_terminal_state_is_final_and_produces_one_terminal_row(
    repository: OperationRepository,
) -> None:
    actor = actor_for(TENANT_A, ACTOR_A)
    created = repository.create_or_restore(
        actor=actor, client_request_id="req-terminal", conversation_id=None, now=FIXED_NOW
    )
    operation_id = created.operation.operation_id

    repository.transition(
        actor=actor, operation_id=operation_id, target=OperationState.RUNNING, now=FIXED_NOW
    )
    completed = repository.transition(
        actor=actor,
        operation_id=operation_id,
        target=OperationState.COMPLETED,
        now=FIXED_NOW,
        checkpoint_seq=3,
    )
    assert completed.state is OperationState.COMPLETED
    assert completed.checkpoint_seq == 3

    for forbidden in (OperationState.RUNNING, OperationState.RECEIVED, OperationState.WAITING):
        with pytest.raises(InvalidState):
            repository.transition(
                actor=actor, operation_id=operation_id, target=forbidden, now=FIXED_NOW
            )

    # Re-requesting the same terminal state is a durable no-op, not a second effect.
    again = repository.transition(
        actor=actor, operation_id=operation_id, target=OperationState.COMPLETED, now=FIXED_NOW
    )
    assert again == completed

    # Read through the BYPASSRLS guard so "exactly one terminal row" is a global
    # claim rather than one scoped to the caller.
    admin = migration_engine()
    with admin.begin() as connection:
        connection.execute(text("SET LOCAL ROLE nexora_rls_guard"))
        terminal_rows = connection.execute(
            text(
                """SELECT count(*) FROM nexora_agent.agent_operations
                WHERE id = :id AND terminal_at IS NOT NULL"""
            ),
            {"id": operation_id},
        ).scalar_one()
        connection.execute(text("RESET ROLE"))
    assert terminal_rows == 1


@pytest.mark.integration
def test_unknown_outcome_is_resolved_from_postgres_before_retry(
    repository: OperationRepository,
) -> None:
    """A caller that lost the response reads durable state instead of re-executing."""
    actor = actor_for(TENANT_A, ACTOR_A)
    created = repository.create_or_restore(
        actor=actor, client_request_id="req-unknown", conversation_id=None, now=FIXED_NOW
    )
    operation_id = created.operation.operation_id
    repository.transition(
        actor=actor, operation_id=operation_id, target=OperationState.RUNNING, now=FIXED_NOW
    )
    repository.transition(
        actor=actor,
        operation_id=operation_id,
        target=OperationState.COMPLETED,
        now=FIXED_NOW,
        checkpoint_seq=4,
    )

    # The client never saw the response and retries the identical request.
    retried = repository.create_or_restore(
        actor=actor, client_request_id="req-unknown", conversation_id=None, now=FIXED_NOW
    )

    assert retried.created is False
    assert retried.operation.state is OperationState.COMPLETED
    assert retried.operation.checkpoint_seq == 4
    assert _count_operations() == 1


@pytest.mark.integration
def test_checkpoint_sequence_never_rewinds(repository: OperationRepository) -> None:
    actor = actor_for(TENANT_A, ACTOR_A)
    created = repository.create_or_restore(
        actor=actor, client_request_id="req-seq", conversation_id=None, now=FIXED_NOW
    )
    operation_id = created.operation.operation_id
    repository.transition(
        actor=actor,
        operation_id=operation_id,
        target=OperationState.RUNNING,
        now=FIXED_NOW,
        checkpoint_seq=7,
    )

    with pytest.raises(InvalidState):
        repository.transition(
            actor=actor,
            operation_id=operation_id,
            target=OperationState.COMPLETED,
            now=FIXED_NOW,
            checkpoint_seq=6,
        )

    assert repository.load(actor=actor, operation_id=operation_id).checkpoint_seq == 7


@pytest.mark.integration
def test_active_count_is_scoped_to_the_calling_actor(repository: OperationRepository) -> None:
    actor_a = actor_for(TENANT_A, ACTOR_A)
    actor_b = actor_for(TENANT_B, ACTOR_B)
    for index in range(3):
        repository.create_or_restore(
            actor=actor_a,
            client_request_id=f"req-load-{index}",
            conversation_id=None,
            now=FIXED_NOW,
        )
    repository.create_or_restore(
        actor=actor_b, client_request_id="req-load-b", conversation_id=None, now=FIXED_NOW
    )

    assert repository.active_count(actor=actor_a) == 3
    assert repository.active_count(actor=actor_b) == 1


@pytest.mark.integration
def test_creation_writes_no_business_row(repository: OperationRepository) -> None:
    actor = actor_for(TENANT_A, ACTOR_A)
    repository.create_or_restore(
        actor=actor, client_request_id="req-no-business", conversation_id=None, now=FIXED_NOW
    )

    sessions = runtime_sessions()
    with sessions() as session, session.begin():
        set_request_context(session, TENANT_A, ACTOR_A)
        for table in ("foundation_mutations", "domain_events", "outbox_events", "audit_events"):
            count = session.execute(text(f"SELECT count(*) FROM {table}")).scalar_one()
            assert count == 0, table
