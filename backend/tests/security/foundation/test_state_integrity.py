from datetime import timedelta
from uuid import UUID

import pytest
from backend.tests.integration.foundation.support import (
    ACTOR_A,
    FIXED_NOW,
    TENANT_A,
    migration_engine,
    owner_actor,
    reset_tenant_data,
    runtime_sessions,
    seed_tenant,
)
from sqlalchemy import text
from sqlalchemy.exc import DBAPIError

from app.db import set_request_context
from app.events import FoundationMutationService
from app.events.outbox import claim_next, mark_failed


@pytest.mark.security
def test_runtime_sql_cannot_rewrite_terminal_idempotency_or_recover_outbox() -> None:
    admin = migration_engine()
    reset_tenant_data(admin)
    seed_tenant(admin, TENANT_A, ACTOR_A, "tenant-a")
    sessions = runtime_sessions()
    FoundationMutationService(sessions).execute(
        actor=owner_actor(),
        operation="foundation.test_mutation",
        idempotency_key="terminal-integrity-001",
        arguments={"value": "original"},
        now=FIXED_NOW,
    )
    with pytest.raises(DBAPIError, match="invalid idempotency transition"):
        with sessions() as session, session.begin():
            set_request_context(session, TENANT_A, ACTOR_A)
            session.execute(
                text(
                    """UPDATE idempotency_records
                    SET stored_result = CAST(:result AS jsonb)
                    WHERE state = 'SUCCEEDED'"""
                ),
                {"result": '{"result":{"accepted":false}}'},
            )

    with sessions() as session, session.begin():
        set_request_context(session, TENANT_A, ACTOR_A)
        session.execute(
            text(
                """INSERT INTO idempotency_records (
                id, tenant_id, actor_id, operation, idempotency_key, request_hash,
                contract_version, state, stored_result, stored_error, lease_expires_at,
                expires_at, created_at, updated_at)
                VALUES (:id, :tenant, :actor, 'foundation.test_mutation', 'malformed', :hash,
                1, 'IN_PROGRESS', NULL, NULL, :lease, :expires, :now, :now)"""
            ),
            {
                "id": UUID("b0000000-0000-0000-0000-000000000001"),
                "tenant": TENANT_A,
                "actor": ACTOR_A,
                "hash": "0" * 64,
                "lease": FIXED_NOW + timedelta(minutes=5),
                "expires": FIXED_NOW + timedelta(days=7),
                "now": FIXED_NOW,
            },
        )
    with pytest.raises(DBAPIError, match="state_fields"):
        with sessions() as session, session.begin():
            set_request_context(session, TENANT_A, ACTOR_A)
            session.execute(
                text(
                    """UPDATE idempotency_records SET state = 'SUCCEEDED',
                    lease_expires_at = NULL WHERE id = :id"""
                ),
                {"id": UUID("b0000000-0000-0000-0000-000000000001")},
            )

    with pytest.raises(DBAPIError, match="invalid outbox transition"):
        with sessions() as session, session.begin():
            set_request_context(session, TENANT_A, ACTOR_A)
            session.execute(text("UPDATE outbox_events SET state = 'CLAIMED'"))

    with sessions() as session, session.begin():
        set_request_context(session, TENANT_A, ACTOR_A)
        claimed = claim_next(session, now=FIXED_NOW, lease=timedelta(seconds=30))
        assert claimed is not None
        assert mark_failed(session, event_id=claimed.id, error_code="DELIVERY_REJECTED")
    with pytest.raises(DBAPIError, match="authorized audit"):
        with sessions() as session, session.begin():
            set_request_context(session, TENANT_A, ACTOR_A)
            session.execute(
                text(
                    """UPDATE outbox_events SET state = 'PENDING', available_at = :now,
                    claimed_at = NULL, lease_expires_at = NULL, last_error_code = NULL
                    WHERE id = :id"""
                ),
                {"now": FIXED_NOW + timedelta(minutes=1), "id": claimed.id},
            )
