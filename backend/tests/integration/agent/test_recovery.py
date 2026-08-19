"""P02-004 — crash, conflict and resume.

Every failure here is injected at a named point, so these are deterministic tests
of recovery rather than hopeful ones. The assertions are all about counts of
durable things: one operation, one terminal event, no repeated node.
"""

import json
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from typing import Any
from uuid import UUID

import pytest
from backend.tests.integration.agent.support import (
    ACTOR_A,
    FIXED_NOW,
    TENANT_A,
    actor_for,
    count_all,
    migration_engine,
    reset_agent_data,
    runtime_sessions,
    seed_both_tenants,
)
from sqlalchemy import text

from app.agent.checkpointer import PostgresCheckpointSaver
from app.agent.contracts import StreamEventType
from app.agent.crypto import AesGcmCheckpointCipher
from app.agent.errors import CheckpointConflict
from app.agent.events import EventLedger
from app.agent.model import DeterministicModelAdapter
from app.agent.operations import OperationRepository
from app.agent.runtime import AgentRuntime, FailurePoint, InjectedCrash
from app.agent.state import OperationState
from app.config import Settings
from app.contracts import ActorContext

FIXTURE = Path("backend/tests/fixtures/agent/crash-after-checkpoint.json")


def _fixture() -> dict[str, Any]:
    loaded: dict[str, Any] = json.loads(FIXTURE.read_text())
    return loaded


def _runtime(
    failure_point: FailurePoint = FailurePoint.NONE,
    dependency_failures_remaining: int = 0,
) -> AgentRuntime:
    """A fresh runtime, as a restarted worker would build one."""
    settings = Settings(environment="test")
    sessions = runtime_sessions()
    return AgentRuntime(
        sessions=sessions,
        operations=OperationRepository(sessions=sessions),
        events=EventLedger(sessions=sessions),
        model=DeterministicModelAdapter(settings),
        cipher=AesGcmCheckpointCipher.from_settings(settings),
        clock=lambda: FIXED_NOW,
        failure_point=failure_point,
        dependency_failures_remaining=dependency_failures_remaining,
    )


def _start(runtime: AgentRuntime, actor: ActorContext, client_request_id: str) -> Any:
    return runtime.operations.create_or_restore(
        actor=actor, client_request_id=client_request_id, conversation_id=None, now=FIXED_NOW
    ).operation


def _event_types(runtime: AgentRuntime, actor: ActorContext, operation_id: UUID) -> list[str]:
    return [
        event.type.value for event in runtime.events.read(actor=actor, operation_id=operation_id)
    ]


def _terminal_event_count(operation_id: UUID) -> int:
    admin = migration_engine()
    with admin.begin() as connection:
        connection.execute(text("SET LOCAL ROLE nexora_rls_guard"))
        count = connection.execute(
            text(
                """SELECT count(*) FROM nexora_agent.agent_operation_events
                WHERE operation_id = :id AND type = 'stream.completed'"""
            ),
            {"id": operation_id},
        ).scalar_one()
        connection.execute(text("RESET ROLE"))
    return int(count)


@pytest.fixture
def prepared() -> None:
    admin = migration_engine()
    seed_both_tenants(admin)
    reset_agent_data(admin)


@pytest.mark.integration
def test_crash_after_checkpoint_resumes_once(prepared: None) -> None:
    fixture = _fixture()
    actor = actor_for(TENANT_A, ACTOR_A)

    # --- attempt one: crashes after the checkpoint, before the caller responds ---
    crashing = _runtime(FailurePoint.AFTER_CHECKPOINT_BEFORE_RESPONSE)
    operation = _start(crashing, actor, fixture["client_request_id"])
    with pytest.raises(InjectedCrash):
        crashing.execute(actor=actor, operation=operation, message=fixture["message"])

    durable_seq = crashing.durable_checkpoint_seq(actor=actor, operation=operation)
    assert durable_seq is not None, "the crash must land after a durable checkpoint"
    assert _terminal_event_count(operation.operation_id) == 0

    # --- attempt two: a brand-new runtime retries the identical client request ---
    resumed_runtime = _runtime()
    retried = resumed_runtime.operations.create_or_restore(
        actor=actor,
        client_request_id=fixture["client_request_id"],
        conversation_id=None,
        now=FIXED_NOW,
    )
    assert retried.created is False, "the retry must not create a second operation"
    assert retried.operation.operation_id == operation.operation_id

    result = resumed_runtime.execute(
        actor=actor, operation=retried.operation, message=fixture["message"]
    )

    assert result.state.status is OperationState(fixture["expected_terminal_status"])
    assert result.state.messages[-1].content == fixture["expected_reply"]
    assert result.state.checkpoint_seq == fixture["expected_final_checkpoint_seq"]

    # One operation, one terminal event, no duplicate effect.
    assert count_all(migration_engine(), "agent_operations") == fixture["expected_operation_count"]
    assert _terminal_event_count(operation.operation_id) == fixture["expected_terminal_event_count"]

    types = _event_types(resumed_runtime, actor, operation.operation_id)
    assert types.count(StreamEventType.STREAM_COMPLETED.value) == 1
    assert types[-1] == StreamEventType.STREAM_COMPLETED.value
    # The completed message is announced exactly once despite the crash and retry.
    assert types.count(StreamEventType.MESSAGE_COMPLETED.value) == 1


@pytest.mark.integration
def test_response_lost_after_durable_completion_returns_the_first_result(
    prepared: None,
) -> None:
    """The client never saw the answer. The retry must not re-execute anything."""
    actor = actor_for(TENANT_A, ACTOR_A)
    crashing = _runtime(FailurePoint.AFTER_TERMINAL_BEFORE_RESPONSE)
    operation = _start(crashing, actor, "lost-response")

    with pytest.raises(InjectedCrash):
        crashing.execute(actor=actor, operation=operation, message="status of the runtime")

    # The operation is already durably terminal.
    stored = crashing.operations.load(actor=actor, operation_id=operation.operation_id)
    assert stored.state is OperationState.COMPLETED

    retry_runtime = _runtime()
    result = retry_runtime.execute(actor=actor, operation=stored, message="status of the runtime")

    assert result.resumed is True
    assert result.operation.state is OperationState.COMPLETED
    assert result.state.messages[-1].content == "echo: status of the runtime"
    assert count_all(migration_engine(), "agent_operations") == 1


@pytest.mark.integration
def test_two_workers_resuming_concurrently_produce_one_terminal_event(
    prepared: None,
) -> None:
    actor = actor_for(TENANT_A, ACTOR_A)
    seed = _runtime(FailurePoint.AFTER_CHECKPOINT_BEFORE_RESPONSE)
    operation = _start(seed, actor, "concurrent-resume")
    with pytest.raises(InjectedCrash):
        seed.execute(actor=actor, operation=operation, message="status of the runtime")

    def resume() -> str:
        runtime = _runtime()
        try:
            runtime.execute(actor=actor, operation=operation, message="status of the runtime")
            return "ok"
        except Exception as error:
            return type(error).__name__

    with ThreadPoolExecutor(max_workers=2) as pool:
        outcomes = [future.result() for future in [pool.submit(resume) for _ in range(2)]]

    assert len(outcomes) == 2
    # Whatever each worker experienced, the durable truth is singular.
    assert _terminal_event_count(operation.operation_id) == 1
    assert count_all(migration_engine(), "agent_operations") == 1

    final = _runtime().operations.load(actor=actor, operation_id=operation.operation_id)
    assert final.state is OperationState.COMPLETED


@pytest.mark.integration
def test_stale_checkpoint_write_is_refused_and_latest_sequence_survives(
    prepared: None,
) -> None:
    """A writer holding an old sequence must lose, and must be told CHECKPOINT_CONFLICT."""
    actor = actor_for(TENANT_A, ACTOR_A)
    runtime = _runtime()
    operation = _start(runtime, actor, "stale-checkpoint")
    runtime.execute(actor=actor, operation=operation, message="status of the runtime")

    latest = runtime.durable_checkpoint_seq(actor=actor, operation=operation)
    assert latest is not None

    settings = Settings(environment="test")
    sessions = runtime_sessions()
    saver = PostgresCheckpointSaver(
        sessions=sessions,
        cipher=AesGcmCheckpointCipher.from_settings(settings),
        actor=actor,
        clock=lambda: FIXED_NOW,
    )
    config = {"configurable": {"thread_id": operation.thread_id}}
    stored = saver.get_tuple(config)
    assert stored is not None

    # Re-writing an already-durable checkpoint id collides on the primary key, and
    # a new checkpoint at an already-taken sequence collides on the sequence index.
    # Both must surface as CHECKPOINT_CONFLICT rather than a raw database error.
    with pytest.raises(CheckpointConflict):
        saver.put(config, stored.checkpoint, stored.metadata, {})

    assert runtime.durable_checkpoint_seq(actor=actor, operation=operation) == latest
    assert _terminal_event_count(operation.operation_id) == 1


@pytest.mark.integration
def test_dependency_timeout_is_bounded_and_then_fails_safely(prepared: None) -> None:
    actor = actor_for(TENANT_A, ACTOR_A)
    runtime = _runtime(FailurePoint.DEPENDENCY_TIMEOUT, dependency_failures_remaining=99)
    operation = _start(runtime, actor, "dependency-timeout")

    from app.agent.errors import DependencyTimeout
    from app.agent.runtime import MAX_DEPENDENCY_ATTEMPTS

    with pytest.raises(DependencyTimeout) as captured:
        runtime.execute(actor=actor, operation=operation, message="status of the runtime")

    assert captured.value.status_code == 504
    assert captured.value.retryable is True
    # Bounded: the retry loop stopped at the configured limit rather than spinning.
    assert runtime._observed_attempts == MAX_DEPENDENCY_ATTEMPTS
    # No terminal event was fabricated for a run that never completed.
    assert _terminal_event_count(operation.operation_id) == 0


@pytest.mark.integration
def test_resume_does_not_repeat_completed_nodes(prepared: None) -> None:
    fixture = _fixture()
    actor = actor_for(TENANT_A, ACTOR_A)
    crashing = _runtime(FailurePoint.AFTER_CHECKPOINT_BEFORE_RESPONSE)
    operation = _start(crashing, actor, "no-repeat")
    with pytest.raises(InjectedCrash):
        crashing.execute(actor=actor, operation=operation, message=fixture["message"])

    resumed = _runtime()
    result = resumed.execute(actor=actor, operation=operation, message=fixture["message"])

    # The reply appears exactly once, so the answer node did not run twice.
    replies = [
        message for message in result.state.messages if message.content == fixture["expected_reply"]
    ]
    assert len(replies) == 1
    assert result.state.checkpoint_seq == fixture["expected_final_checkpoint_seq"]
