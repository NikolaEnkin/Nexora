"""The durable lifecycle event ledger, before any HTTP layer exists.

The ledger is what makes SSE reconnect work across a restart, so it is proved
here against PostgreSQL rather than against an in-process queue.
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
from sqlalchemy.exc import DBAPIError

from app.agent.contracts import (
    MessageCompletedData,
    MessageDeltaData,
    OperationStartedData,
    StateChangedData,
    StreamCompletedData,
    StreamEventType,
)
from app.agent.crypto import AesGcmCheckpointCipher
from app.agent.errors import OperationNotFound
from app.agent.events import EventLedger
from app.agent.identity import derive_event_id
from app.agent.operations import OperationRepository
from app.agent.state import OperationState, ReasonCode
from app.config import Settings
from app.db import set_request_context

CONCURRENT_WRITERS = 10


@pytest.fixture
def ledger() -> tuple[EventLedger, OperationRepository]:
    admin = migration_engine()
    seed_both_tenants(admin)
    reset_agent_data(admin)
    sessions = runtime_sessions(pool_size=CONCURRENT_WRITERS + 2)
    return EventLedger(
        sessions=sessions, cipher=AesGcmCheckpointCipher.from_settings(Settings(environment="test"))
    ), OperationRepository(sessions=sessions)


@pytest.mark.integration
def test_events_are_ordered_stable_and_monotonic(
    ledger: tuple[EventLedger, OperationRepository],
) -> None:
    events, operations = ledger
    actor = actor_for(TENANT_A, ACTOR_A)
    operation = operations.create_or_restore(
        actor=actor, client_request_id="ledger-order", conversation_id=None, now=FIXED_NOW
    ).operation

    appended = [
        events.append(
            actor=actor,
            operation_id=operation.operation_id,
            event_type=StreamEventType.OPERATION_STARTED,
            data=OperationStartedData(conversation_id=operation.conversation_id),
            now=FIXED_NOW,
        ),
        events.append(
            actor=actor,
            operation_id=operation.operation_id,
            event_type=StreamEventType.OPERATION_STATE_CHANGED,
            data=StateChangedData(
                state=OperationState.RUNNING, reason_code=ReasonCode.NODE_ADVANCED
            ),
            now=FIXED_NOW,
        ),
        events.append(
            actor=actor,
            operation_id=operation.operation_id,
            event_type=StreamEventType.MESSAGE_DELTA,
            data=MessageDeltaData(
                message_id=UUID("c0000000-0000-0000-0000-000000000001"), index=0, text="echo:"
            ),
            now=FIXED_NOW,
        ),
    ]

    assert [event.sequence for event in appended] == [1, 2, 3]
    # Stable identity: the same (operation, sequence) always yields the same id.
    for event in appended:
        assert event.event_id == derive_event_id(operation.operation_id, event.sequence)

    stored = events.read(actor=actor, operation_id=operation.operation_id)
    assert [event.sequence for event in stored] == [1, 2, 3]
    assert [event.type for event in stored] == [
        StreamEventType.OPERATION_STARTED,
        StreamEventType.OPERATION_STATE_CHANGED,
        StreamEventType.MESSAGE_DELTA,
    ]
    assert stored == appended
    assert all(event.version == "1" for event in stored)

    # Replay from a boundary returns only what comes after it.
    assert [
        event.sequence
        for event in events.read(actor=actor, operation_id=operation.operation_id, after_sequence=1)
    ] == [2, 3]
    assert events.read(actor=actor, operation_id=operation.operation_id, after_sequence=3) == []


@pytest.mark.integration
def test_terminal_event_happens_exactly_once(
    ledger: tuple[EventLedger, OperationRepository],
) -> None:
    events, operations = ledger
    actor = actor_for(TENANT_A, ACTOR_A)
    operation = operations.create_or_restore(
        actor=actor, client_request_id="ledger-terminal", conversation_id=None, now=FIXED_NOW
    ).operation

    first = events.append(
        actor=actor,
        operation_id=operation.operation_id,
        event_type=StreamEventType.STREAM_COMPLETED,
        data=StreamCompletedData(final_state=OperationState.COMPLETED),
        now=FIXED_NOW,
    )
    # A second attempt converges on the first rather than creating a duplicate.
    second = events.append(
        actor=actor,
        operation_id=operation.operation_id,
        event_type=StreamEventType.STREAM_COMPLETED,
        data=StreamCompletedData(final_state=OperationState.COMPLETED),
        now=FIXED_NOW,
    )

    assert second == first
    assert count_all(migration_engine(), "agent_operation_events") == 1


@pytest.mark.integration
def test_concurrent_terminal_appends_still_produce_one_event(
    ledger: tuple[EventLedger, OperationRepository],
) -> None:
    events, operations = ledger
    actor = actor_for(TENANT_A, ACTOR_A)
    operation = operations.create_or_restore(
        actor=actor, client_request_id="ledger-race", conversation_id=None, now=FIXED_NOW
    ).operation

    def close() -> UUID:
        return events.append(
            actor=actor,
            operation_id=operation.operation_id,
            event_type=StreamEventType.STREAM_COMPLETED,
            data=StreamCompletedData(final_state=OperationState.COMPLETED),
            now=FIXED_NOW,
        ).event_id

    with ThreadPoolExecutor(max_workers=CONCURRENT_WRITERS) as pool:
        ids = [f.result() for f in [pool.submit(close) for _ in range(CONCURRENT_WRITERS)]]

    assert len(set(ids)) == 1
    assert count_all(migration_engine(), "agent_operation_events") == 1


@pytest.mark.integration
def test_concurrent_appends_keep_the_sequence_unique(
    ledger: tuple[EventLedger, OperationRepository],
) -> None:
    events, operations = ledger
    actor = actor_for(TENANT_A, ACTOR_A)
    operation = operations.create_or_restore(
        actor=actor, client_request_id="ledger-seq-race", conversation_id=None, now=FIXED_NOW
    ).operation

    def emit(index: int) -> int:
        return events.append(
            actor=actor,
            operation_id=operation.operation_id,
            event_type=StreamEventType.MESSAGE_DELTA,
            data=MessageDeltaData(
                message_id=UUID("c0000000-0000-0000-0000-000000000001"),
                index=index,
                text=f"delta-{index}",
            ),
            now=FIXED_NOW,
        ).sequence

    with ThreadPoolExecutor(max_workers=CONCURRENT_WRITERS) as pool:
        sequences = [f.result() for f in [pool.submit(emit, i) for i in range(CONCURRENT_WRITERS)]]

    assert sorted(sequences) == list(range(1, CONCURRENT_WRITERS + 1))
    assert len(set(sequences)) == CONCURRENT_WRITERS
    assert count_all(migration_engine(), "agent_operation_events") == CONCURRENT_WRITERS


@pytest.mark.integration
def test_unregistered_type_and_state_cannot_be_stored(
    ledger: tuple[EventLedger, OperationRepository],
) -> None:
    events, operations = ledger
    actor = actor_for(TENANT_A, ACTOR_A)
    operation = operations.create_or_restore(
        actor=actor, client_request_id="ledger-invalid", conversation_id=None, now=FIXED_NOW
    ).operation

    # The registry rejects a mismatched payload before any SQL runs.
    with pytest.raises(TypeError):
        events.append(
            actor=actor,
            operation_id=operation.operation_id,
            event_type=StreamEventType.MESSAGE_DELTA,
            data=StreamCompletedData(final_state=OperationState.COMPLETED),
            now=FIXED_NOW,
        )

    # And the database refuses an unregistered type even by direct insert.
    sessions = runtime_sessions()
    with sessions() as session:
        transaction = session.begin()
        set_request_context(session, TENANT_A, ACTOR_A)
        with pytest.raises(DBAPIError):
            session.execute(
                text(
                    """INSERT INTO nexora_agent.agent_operation_events (
                        id, tenant_id, actor_id, operation_id, sequence, type, data,
                        contract_version, emitted_at, created_at
                    ) VALUES (
                        :id, :tenant_id, :actor_id, :operation_id, 99, 'robot.animate',
                        CAST('{}' AS jsonb), 1, :now, :now
                    )"""
                ),
                {
                    "id": derive_event_id(operation.operation_id, 99),
                    "tenant_id": TENANT_A,
                    "actor_id": ACTOR_A,
                    "operation_id": operation.operation_id,
                    "now": FIXED_NOW,
                },
            )
        transaction.rollback()

    assert count_all(migration_engine(), "agent_operation_events") == 0


@pytest.mark.integration
def test_stored_events_cannot_be_rewritten(
    ledger: tuple[EventLedger, OperationRepository],
) -> None:
    events, operations = ledger
    actor = actor_for(TENANT_A, ACTOR_A)
    operation = operations.create_or_restore(
        actor=actor, client_request_id="ledger-append-only", conversation_id=None, now=FIXED_NOW
    ).operation
    events.append(
        actor=actor,
        operation_id=operation.operation_id,
        event_type=StreamEventType.MESSAGE_COMPLETED,
        data=MessageCompletedData(
            message_id=UUID("c0000000-0000-0000-0000-000000000001"), text="echo: hello there"
        ),
        now=FIXED_NOW,
    )

    sessions = runtime_sessions()
    for statement in (
        "UPDATE nexora_agent.agent_operation_events SET type = 'operation.failed'",
        "DELETE FROM nexora_agent.agent_operation_events",
    ):
        with sessions() as session:
            transaction = session.begin()
            set_request_context(session, TENANT_A, ACTOR_A)
            with pytest.raises(DBAPIError):
                session.execute(text(statement))
            transaction.rollback()

    stored = events.read(actor=actor, operation_id=operation.operation_id)
    assert len(stored) == 1
    assert stored[0].type is StreamEventType.MESSAGE_COMPLETED


@pytest.mark.integration
def test_events_are_invisible_to_another_tenant(
    ledger: tuple[EventLedger, OperationRepository],
) -> None:
    events, operations = ledger
    owner = actor_for(TENANT_A, ACTOR_A)
    operation = operations.create_or_restore(
        actor=owner, client_request_id="ledger-isolation", conversation_id=None, now=FIXED_NOW
    ).operation
    events.append(
        actor=owner,
        operation_id=operation.operation_id,
        event_type=StreamEventType.OPERATION_STARTED,
        data=OperationStartedData(conversation_id=operation.conversation_id),
        now=FIXED_NOW,
    )

    intruder = actor_for(TENANT_B, ACTOR_B)
    assert events.read(actor=intruder, operation_id=operation.operation_id) == []
    assert events.terminal_event(actor=intruder, operation_id=operation.operation_id) is None
    # Appending to a foreign operation is refused with the same non-disclosing error.
    with pytest.raises(OperationNotFound):
        events.append(
            actor=intruder,
            operation_id=operation.operation_id,
            event_type=StreamEventType.STREAM_COMPLETED,
            data=StreamCompletedData(final_state=OperationState.COMPLETED),
            now=FIXED_NOW,
        )

    assert len(events.read(actor=owner, operation_id=operation.operation_id)) == 1
    assert count_all(migration_engine(), "agent_operation_events") == 1
