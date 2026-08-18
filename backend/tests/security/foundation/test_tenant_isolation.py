import json
from pathlib import Path
from uuid import UUID

import pytest
from backend.tests.integration.foundation.support import (
    ACTOR_A,
    ACTOR_B,
    FIXED_NOW,
    TENANT_A,
    TENANT_B,
    migration_engine,
    owner_actor,
    reset_tenant_data,
    runtime_sessions,
    seed_tenant,
)
from sqlalchemy import text
from sqlalchemy.exc import DBAPIError

from app.db import set_request_context
from app.errors import AuthorizationDenied
from app.identity.repository import TenantUserRepository


@pytest.mark.security
def test_pool_context_and_guessed_id_fail_closed() -> None:
    fixture = json.loads(Path("backend/tests/fixtures/foundation/two-tenants.json").read_text())
    assert UUID(fixture["tenant_a"]) == TENANT_A
    assert UUID(fixture["tenant_b"]) == TENANT_B
    assert UUID(fixture["actor_a"]) == ACTOR_A
    assert UUID(fixture["actor_b"]) == ACTOR_B
    admin = migration_engine()
    reset_tenant_data(admin)
    seed_tenant(admin, TENANT_A, ACTOR_A, "tenant-a")
    seed_tenant(admin, TENANT_B, ACTOR_B, "tenant-b")
    sessions = runtime_sessions(pool_size=1)

    with sessions() as session, session.begin():
        first_backend = session.execute(text("SELECT pg_backend_pid()")).scalar_one()
        set_request_context(session, TENANT_A, ACTOR_A)
        assert session.execute(text("SELECT id FROM users")).scalars().all() == [ACTOR_A]
    with sessions() as session, session.begin():
        assert session.execute(text("SELECT pg_backend_pid()")).scalar_one() == first_backend
        set_request_context(session, TENANT_B, ACTOR_B)
        assert session.execute(text("SELECT id FROM users")).scalars().all() == [ACTOR_B]
    with sessions() as session, session.begin():
        assert session.execute(text("SELECT pg_backend_pid()")).scalar_one() == first_backend
        assert session.execute(text("SELECT id FROM users")).scalars().all() == []
    with sessions() as session, session.begin():
        session.execute(
            text(
                "SELECT set_config('app.tenant_id', :tenant, true), "
                "set_config('app.actor_id', :actor, true), "
                "set_config('app.context_signature', 'forged', true)"
            ),
            {"tenant": str(TENANT_A), "actor": str(ACTOR_A)},
        )
        assert session.execute(text("SELECT id FROM users")).scalars().all() == []
    with pytest.raises(DBAPIError):
        with sessions() as session, session.begin():
            session.execute(
                text(
                    "SELECT set_config('app.tenant_id', :tenant, true), "
                    "set_config('app.actor_id', :actor, true), "
                    "set_config('app.context_signature', 'forged', true)"
                ),
                {"tenant": str(TENANT_A), "actor": str(ACTOR_A)},
            )
            session.execute(
                text(
                    """INSERT INTO foundation_mutations
                    (id, tenant_id, actor_id, operation, payload_hash, result, created_at)
                    VALUES ('60000000-0000-0000-0000-000000000001', :tenant, :actor,
                    'forged', :hash, '{}'::jsonb, :now)"""
                ),
                {"tenant": TENANT_A, "actor": ACTOR_A, "hash": "0" * 64, "now": FIXED_NOW},
            )
    zero_actor = UUID("00000000-0000-0000-0000-000000000000")
    with sessions() as session, session.begin():
        set_request_context(session, TENANT_A, zero_actor)
        assert session.execute(text("SELECT id FROM users")).scalars().all() == []
    with sessions() as session, session.begin():
        set_request_context(session, TENANT_A, ACTOR_B)
        assert session.execute(text("SELECT id FROM users")).scalars().all() == []

    repository = TenantUserRepository(sessions)
    assert (
        repository.get_display_label(owner_actor(TENANT_B, ACTOR_B), ACTOR_A, now=FIXED_NOW) is None
    )
    unauthorized = owner_actor(TENANT_B, ACTOR_B).model_copy(update={"permissions": ()})
    with pytest.raises(AuthorizationDenied):
        repository.get_display_label(unauthorized, ACTOR_B, now=FIXED_NOW)
    with sessions() as session, session.begin():
        set_request_context(session, TENANT_B, ACTOR_B)
        denials = session.execute(
            text(
                """SELECT result, reason, target_id FROM audit_events
                WHERE action = 'user.read' ORDER BY target_id"""
            )
        ).all()
        assert {tuple(row) for row in denials} == {
            ("DENIED", "AUTHORIZATION_DENIED", ACTOR_A),
            ("DENIED", "AUTHORIZATION_DENIED", ACTOR_B),
        }
        assert session.execute(text("SELECT count(*) FROM users")).scalar_one() == 1
