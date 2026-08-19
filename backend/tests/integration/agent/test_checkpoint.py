"""P02-003 — durable checkpoints restore exact state and sequence across a restart.

"Restart" here is real: the compiled graph, the saver, the cipher and the session
factory are all discarded and rebuilt from configuration, so nothing survives in
memory between the two halves of the test.
"""

import json
from pathlib import Path
from typing import Any
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

from app.agent.checkpointer import (
    PostgresCheckpointSaver,
    agent_state_from_checkpoint,
    latest_checkpoint_seq,
)
from app.agent.crypto import AesGcmCheckpointCipher
from app.agent.errors import RuntimeInternalError
from app.agent.graph import build_graph
from app.agent.identity import derive_thread_id
from app.agent.model import DeterministicModelAdapter
from app.agent.operations import OperationRepository
from app.agent.state import (
    AgentMessage,
    AgentRoute,
    AgentState,
    MessageRole,
    OperationState,
    parse_agent_state_v1,
)
from app.config import Settings
from app.contracts import ActorContext
from app.db import set_request_context
from app.db.engine import context_signature

FIXTURE = Path("backend/tests/fixtures/agent/checkpoint-run.json")


def _fixture() -> dict[str, Any]:
    loaded: dict[str, Any] = json.loads(FIXTURE.read_text())
    return loaded


def _settings() -> Settings:
    return Settings(environment="test")


def _runtime(actor: ActorContext) -> tuple[Any, PostgresCheckpointSaver]:
    """Construct a completely fresh runtime, as a restarted process would."""
    settings = _settings()
    saver = PostgresCheckpointSaver(
        sessions=runtime_sessions(),
        cipher=AesGcmCheckpointCipher.from_settings(settings),
        actor=actor,
        clock=lambda: FIXED_NOW,
    )
    graph = build_graph(
        model=DeterministicModelAdapter(settings),
        clock=lambda: FIXED_NOW,
        checkpointer=saver,
    )
    return graph, saver


def _initial_state(actor: ActorContext, operation_id: UUID, conversation_id: UUID, message: str):
    return AgentState(
        tenant_id=actor.tenant_id,
        actor_id=actor.actor_id,
        conversation_id=conversation_id,
        operation_id=operation_id,
        request_id="checkpoint-run-001",
        messages=(
            AgentMessage(
                message_id=UUID("c0000000-0000-0000-0000-000000000001"),
                role=MessageRole.USER,
                content=message,
                created_at=FIXED_NOW,
            ),
        ),
        status=OperationState.RECEIVED,
        correlation_id=actor.correlation_id,
        checkpoint_seq=0,
    )


@pytest.fixture
def prepared() -> OperationRepository:
    admin = migration_engine()
    seed_both_tenants(admin)
    reset_agent_data(admin)
    return OperationRepository(sessions=runtime_sessions())


@pytest.mark.integration
def test_checkpoint_restores_exact_state_sequence(prepared: OperationRepository) -> None:
    fixture = _fixture()
    actor = actor_for(TENANT_A, ACTOR_A)
    created = prepared.create_or_restore(
        actor=actor,
        client_request_id=fixture["client_request_id"],
        conversation_id=None,
        now=FIXED_NOW,
    )
    operation = created.operation
    config = {"configurable": {"thread_id": operation.thread_id}}

    # --- first runtime: run only as far as node two, then persist and discard ---
    graph, _saver = _runtime(actor)
    partial = build_graph(
        model=DeterministicModelAdapter(_settings()),
        clock=lambda: FIXED_NOW,
        checkpointer=_saver,
    )
    state = _initial_state(
        actor, operation.operation_id, operation.conversation_id, fixture["message"]
    )
    interrupted = partial.invoke(state, config, interrupt_after=[fixture["interrupt_after_node"]])
    mid_state = AgentState.model_validate(interrupted)
    assert mid_state.checkpoint_seq == fixture["expected_seq_at_interrupt"]
    assert mid_state.status is OperationState.RUNNING

    durable_seq = latest_checkpoint_seq(runtime_sessions(), actor, operation.thread_id)
    assert durable_seq is not None
    del graph, partial, _saver, state

    # --- second runtime: rebuilt from scratch, nothing shared in memory ---
    reloaded_graph, reloaded_saver = _runtime(actor)
    restored = reloaded_saver.get_tuple(config)
    assert restored is not None
    restored_state = agent_state_from_checkpoint(restored.checkpoint)

    # Exact state restore, not merely a compatible one.
    assert restored_state == mid_state
    assert parse_agent_state_v1(restored_state.model_dump(mode="json")) == mid_state
    assert latest_checkpoint_seq(runtime_sessions(), actor, operation.thread_id) == durable_seq

    # Resuming continues from the checkpoint without repeating completed nodes.
    resumed_nodes = [
        next(iter(update)) for update in reloaded_graph.stream(None, config, stream_mode="updates")
    ]
    assert resumed_nodes == fixture["expected_nodes"][2:]
    assert "receive" not in resumed_nodes
    assert "validate" not in resumed_nodes

    final_tuple = reloaded_saver.get_tuple(config)
    assert final_tuple is not None
    final = agent_state_from_checkpoint(final_tuple.checkpoint)
    assert final.route is AgentRoute(fixture["expected_route"])
    assert final.status is OperationState(fixture["expected_terminal_status"])
    assert final.messages[-1].content == fixture["expected_reply"]
    assert final.checkpoint_seq == fixture["expected_final_checkpoint_seq"]

    # Exactly one tenant/actor-scoped operation, and no business row anywhere.
    assert count_all(migration_engine(), "agent_operations") == 1
    sessions = runtime_sessions()
    with sessions() as session, session.begin():
        set_request_context(session, TENANT_A, ACTOR_A)
        for table in fixture["business_tables_that_must_stay_empty"]:
            assert session.execute(text(f"SELECT count(*) FROM {table}")).scalar_one() == 0, table


@pytest.mark.integration
def test_checkpoints_are_ciphertext_at_rest(prepared: OperationRepository) -> None:
    actor = actor_for(TENANT_A, ACTOR_A)
    created = prepared.create_or_restore(
        actor=actor, client_request_id="cipher-check", conversation_id=None, now=FIXED_NOW
    )
    operation = created.operation
    config = {"configurable": {"thread_id": operation.thread_id}}
    secret = "correct-horse-battery-staple-fixture"

    graph, _ = _runtime(actor)
    graph.invoke(
        _initial_state(actor, operation.operation_id, operation.conversation_id, secret),
        config,
    )

    admin = migration_engine()
    with admin.begin() as connection:
        connection.execute(text("SET LOCAL ROLE nexora_rls_guard"))
        rows = connection.execute(
            text(
                """SELECT checkpoint_ciphertext, metadata_ciphertext
                FROM nexora_agent.agent_checkpoints WHERE thread_id = :thread_id"""
            ),
            {"thread_id": operation.thread_id},
        ).all()
        connection.execute(text("RESET ROLE"))

    assert rows, "the run must have produced checkpoints"
    for checkpoint_blob, metadata_blob in rows:
        assert secret.encode() not in bytes(checkpoint_blob)
        assert secret.encode() not in bytes(metadata_blob)


@pytest.mark.integration
def test_foreign_actor_cannot_restore_the_thread(prepared: OperationRepository) -> None:
    owner = actor_for(TENANT_A, ACTOR_A)
    created = prepared.create_or_restore(
        actor=owner, client_request_id="isolation-thread", conversation_id=None, now=FIXED_NOW
    )
    operation = created.operation
    config = {"configurable": {"thread_id": operation.thread_id}}

    graph, saver = _runtime(owner)
    graph.invoke(
        _initial_state(owner, operation.operation_id, operation.conversation_id, "a question here"),
        config,
    )
    assert saver.get_tuple(config) is not None

    # Another tenant guessing the exact thread key sees nothing at all.
    _, foreign_saver = _runtime(actor_for(TENANT_B, ACTOR_B))
    assert foreign_saver.get_tuple(config) is None
    assert list(foreign_saver.list(config)) == []

    # And a same-tenant actor who is not the owner sees nothing either.
    _, other_actor_saver = _runtime(actor_for(TENANT_A, ACTOR_B))
    assert other_actor_saver.get_tuple(config) is None

    # The owner's state is unchanged by any of those attempts.
    assert saver.get_tuple(config) is not None


@pytest.mark.integration
def test_ciphertext_cannot_be_replayed_into_another_thread(
    prepared: OperationRepository,
) -> None:
    """Identity is bound as AEAD associated data, so a lifted row fails to open."""
    actor = actor_for(TENANT_A, ACTOR_A)
    source = prepared.create_or_restore(
        actor=actor, client_request_id="aad-source", conversation_id=None, now=FIXED_NOW
    ).operation
    target = prepared.create_or_restore(
        actor=actor, client_request_id="aad-target", conversation_id=None, now=FIXED_NOW
    ).operation

    graph, saver = _runtime(actor)
    graph.invoke(
        _initial_state(actor, source.operation_id, source.conversation_id, "a question here"),
        {"configurable": {"thread_id": source.thread_id}},
    )

    # Copy the source ciphertext onto the target thread, exactly as an attacker
    # with write access to the row would.
    admin = migration_engine()
    with admin.begin() as connection:
        connection.execute(text("SET LOCAL ROLE nexora_rls_guard"))
        row = (
            connection.execute(
                text(
                    """SELECT checkpoint_id, checkpoint_seq, state_schema_version, key_id,
                              checkpoint_type, checkpoint_nonce, checkpoint_ciphertext,
                              metadata_type, metadata_nonce, metadata_ciphertext
                    FROM nexora_agent.agent_checkpoints WHERE thread_id = :thread_id
                    ORDER BY checkpoint_seq DESC LIMIT 1"""
                ),
                {"thread_id": source.thread_id},
            )
            .mappings()
            .one()
        )
        connection.execute(text("RESET ROLE"))
    with admin.begin() as connection:
        # Write as the row's own tenant and actor. Forced RLS refuses an
        # unauthenticated insert outright, so this is the strongest case that can
        # actually reach the table: the owner's own ciphertext, relocated to a
        # different thread of theirs.
        connection.execute(
            text(
                "SELECT set_config('app.tenant_id', :tenant, true), "
                "set_config('app.actor_id', :actor, true), "
                "set_config('app.context_signature', :signature, true)"
            ),
            {
                "tenant": str(TENANT_A),
                "actor": str(ACTOR_A),
                "signature": context_signature(
                    TENANT_A,
                    ACTOR_A,
                    Settings(environment="test").rls_context_secret.get_secret_value(),
                ),
            },
        )
        connection.execute(
            text(
                """INSERT INTO nexora_agent.agent_checkpoints (
                    thread_id, checkpoint_ns, checkpoint_id, tenant_id, actor_id,
                    parent_checkpoint_id, checkpoint_seq, state_schema_version, key_id,
                    checkpoint_type, checkpoint_nonce, checkpoint_ciphertext,
                    metadata_type, metadata_nonce, metadata_ciphertext, created_at
                ) VALUES (
                    :thread_id, '', :checkpoint_id, :tenant_id, :actor_id,
                    NULL, 0, :state_schema_version, :key_id,
                    :checkpoint_type, :checkpoint_nonce, :checkpoint_ciphertext,
                    :metadata_type, :metadata_nonce, :metadata_ciphertext, :now
                )"""
            ),
            {
                "thread_id": target.thread_id,
                "tenant_id": TENANT_A,
                "actor_id": ACTOR_A,
                "now": FIXED_NOW,
                **{key: row[key] for key in row if key != "checkpoint_seq"},
                "state_schema_version": row["state_schema_version"],
            },
        )

    with pytest.raises(RuntimeInternalError):
        saver.get_tuple({"configurable": {"thread_id": target.thread_id}})


@pytest.mark.integration
def test_thread_id_is_derived_and_opaque(prepared: OperationRepository) -> None:
    actor = actor_for(TENANT_A, ACTOR_A)
    created = prepared.create_or_restore(
        actor=actor, client_request_id="thread-shape", conversation_id=None, now=FIXED_NOW
    )
    operation = created.operation

    assert operation.thread_id == derive_thread_id(TENANT_A, operation.conversation_id)
    assert len(operation.thread_id) == 32
    assert operation.thread_id.isalnum()
    # Not a display name and not a bare conversation identifier.
    assert "thread-shape" not in operation.thread_id
    assert str(operation.conversation_id) not in operation.thread_id
