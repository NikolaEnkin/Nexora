"""Shared fixtures for Phase-02 integration and security tests.

Builds on the Phase-01 tenant provisioning helpers so agent tests exercise the
same real tenants, users and signed RLS context that the rest of the system uses,
rather than a parallel fake.
"""

from datetime import UTC, datetime
from uuid import UUID

from backend.tests.integration.foundation.support import (
    ACTOR_A,
    ACTOR_B,
    CORRELATION_A,
    CORRELATION_B,
    TENANT_A,
    TENANT_B,
    migration_engine,
    reset_tenant_data,
    runtime_sessions,
    seed_tenant,
)
from sqlalchemy import Engine, text
from sqlalchemy.orm import Session

from app.agent.identity import derive_conversation_id, derive_operation_id, derive_thread_id
from app.agent.state import STATE_SCHEMA_VERSION
from app.contracts import ActorContext

FIXED_NOW = datetime(2026, 1, 15, 10, 0, tzinfo=UTC)

__all__ = [
    "ACTOR_A",
    "ACTOR_B",
    "CORRELATION_A",
    "CORRELATION_B",
    "FIXED_NOW",
    "TENANT_A",
    "TENANT_B",
    "actor_for",
    "count_all",
    "insert_operation",
    "migration_engine",
    "reset_agent_data",
    "reset_tenant_data",
    "runtime_sessions",
    "seed_both_tenants",
    "seed_tenant",
]


def actor_for(tenant_id: UUID, actor_id: UUID) -> ActorContext:
    """An OWNER actor for the given tenant, built by the trusted adapter contract."""
    return ActorContext(
        tenant_id=tenant_id,
        actor_id=actor_id,
        subject=f"auth0|{tenant_id}-owner",
        auth_method="test_fixture",
        roles=("OWNER",),
        permissions=(
            "tenant.read",
            "tenant.manage",
            "membership.read",
            "membership.manage",
            "audit.read",
        ),
        correlation_id=CORRELATION_A if tenant_id == TENANT_A else CORRELATION_B,
    )


def count_all(engine: Engine, table: str) -> int:
    """Count every row in an agent table, across all tenants.

    FORCE RLS hides rows from the table owner as well, so this reads through the
    BYPASSRLS guard role. That is what lets a security negative assert a protected
    side-effect count is genuinely zero rather than merely invisible to the caller.
    """
    if table not in {
        "agent_operations",
        "agent_operation_events",
        "agent_checkpoints",
        "agent_checkpoint_writes",
    }:
        raise ValueError(f"unknown agent table: {table}")
    with engine.begin() as connection:
        connection.execute(text("SET LOCAL ROLE nexora_rls_guard"))
        try:
            return int(
                connection.execute(text(f"SELECT count(*) FROM nexora_agent.{table}")).scalar_one()
            )
        finally:
            connection.execute(text("RESET ROLE"))


def reset_agent_data(engine: Engine) -> None:
    """Clear runtime coordination rows between tests.

    Uses the migrator connection deliberately: the runtime role has no DELETE or
    TRUNCATE privilege anywhere in this schema, which is exactly the property the
    boundary tests assert.
    """
    with engine.begin() as connection:
        connection.execute(
            text(
                """TRUNCATE TABLE nexora_agent.agent_checkpoint_writes,
                nexora_agent.agent_checkpoints, nexora_agent.agent_operation_events,
                nexora_agent.agent_operations CASCADE"""
            )
        )


def seed_both_tenants(engine: Engine) -> None:
    reset_tenant_data(engine)
    seed_tenant(engine, TENANT_A, ACTOR_A, "tenant-a")
    seed_tenant(engine, TENANT_B, ACTOR_B, "tenant-b")


def insert_operation(
    session: Session,
    *,
    tenant_id: UUID,
    actor_id: UUID,
    client_request_id: str,
    state: str = "RECEIVED",
    checkpoint_seq: int = 0,
) -> UUID:
    """Insert one operation row directly, for tests that exercise the DB boundary."""
    operation_id = derive_operation_id(tenant_id, actor_id, client_request_id)
    conversation_id = derive_conversation_id(tenant_id, actor_id, client_request_id)
    session.execute(
        text(
            """INSERT INTO nexora_agent.agent_operations (
                id, tenant_id, actor_id, conversation_id, client_request_id, thread_id,
                state, route, contract_version, state_schema_version, checkpoint_seq,
                error_code, correlation_id, terminal_at, created_at, updated_at
            ) VALUES (
                :id, :tenant_id, :actor_id, :conversation_id, :client_request_id, :thread_id,
                :state, NULL, 1, :state_schema_version, :checkpoint_seq,
                NULL, :correlation_id, NULL, :now, :now
            )"""
        ),
        {
            "id": operation_id,
            "tenant_id": tenant_id,
            "actor_id": actor_id,
            "conversation_id": conversation_id,
            "client_request_id": client_request_id,
            "thread_id": derive_thread_id(tenant_id, conversation_id),
            "state": state,
            "state_schema_version": STATE_SCHEMA_VERSION,
            "checkpoint_seq": checkpoint_seq,
            "correlation_id": CORRELATION_A if tenant_id == TENANT_A else CORRELATION_B,
            "now": FIXED_NOW,
        },
    )
    return operation_id
