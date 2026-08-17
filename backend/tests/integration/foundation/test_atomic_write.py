import json
from pathlib import Path

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

from app.db import set_request_context
from app.errors import AuthorizationDenied
from app.events import FoundationMutationService, InjectedFailure


@pytest.mark.integration
def test_crash_before_commit_leaves_no_partial_state() -> None:
    fixture = json.loads(
        Path("backend/tests/fixtures/foundation/protected-mutation.json").read_text()
    )
    admin = migration_engine()
    reset_tenant_data(admin)
    seed_tenant(admin, TENANT_A, ACTOR_A, "tenant-a")
    sessions = runtime_sessions()
    service = FoundationMutationService(sessions)
    with pytest.raises(InjectedFailure):
        service.execute(
            actor=owner_actor(),
            operation=fixture["operation"],
            idempotency_key=fixture["idempotency_key"],
            arguments={"value": "fixed"},
            now=FIXED_NOW,
            fail_before_commit=fixture["fail_before_commit"],
        )

    with sessions() as session, session.begin():
        set_request_context(session, TENANT_A, ACTOR_A)
        for table in (
            "foundation_mutations",
            "domain_events",
            "outbox_events",
            "idempotency_records",
            "audit_events",
        ):
            assert session.execute(text(f"SELECT count(*) FROM {table}")).scalar_one() == 0


@pytest.mark.integration
def test_authorization_denial_leaves_zero_protected_state() -> None:
    admin = migration_engine()
    reset_tenant_data(admin)
    seed_tenant(admin, TENANT_A, ACTOR_A, "tenant-a")
    sessions = runtime_sessions()
    denied_actor = owner_actor().model_copy(update={"permissions": ()})
    with pytest.raises(AuthorizationDenied):
        FoundationMutationService(sessions).execute(
            actor=denied_actor,
            operation="foundation.test_mutation",
            idempotency_key="denied-key-001",
            arguments={"value": "fixed"},
            now=FIXED_NOW,
        )
    with sessions() as session, session.begin():
        set_request_context(session, TENANT_A, ACTOR_A)
        for table in (
            "foundation_mutations",
            "domain_events",
            "outbox_events",
            "idempotency_records",
            "audit_events",
        ):
            assert session.execute(text(f"SELECT count(*) FROM {table}")).scalar_one() == 0
