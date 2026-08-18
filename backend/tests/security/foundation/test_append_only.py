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


@pytest.mark.security
def test_event_and_audit_are_append_only() -> None:
    admin = migration_engine()
    reset_tenant_data(admin)
    seed_tenant(admin, TENANT_A, ACTOR_A, "tenant-a")
    sessions = runtime_sessions()
    FoundationMutationService(sessions).execute(
        actor=owner_actor(),
        operation="foundation.test_mutation",
        idempotency_key="append-only-key-001",
        arguments={"value": "fixed"},
        now=FIXED_NOW,
    )
    for statement in (
        "UPDATE domain_events SET event_type = 'changed'",
        "DELETE FROM audit_events",
    ):
        with sessions() as session, pytest.raises(DBAPIError):
            with session.begin():
                set_request_context(session, TENANT_A, ACTOR_A)
                session.execute(text(statement))
