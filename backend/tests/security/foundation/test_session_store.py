from datetime import timedelta
from uuid import UUID

import pytest
from backend.tests.integration.foundation.support import (
    ACTOR_A,
    CORRELATION_A,
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

from app.contracts import ActorContext
from app.db import build_session_factory, set_request_context
from app.errors import AuthenticationRequired
from app.identity.session import hash_session_token, validate_csrf_and_origin
from app.identity.session_store import PostgresSessionStore


@pytest.mark.security
def test_postgres_session_is_hashed_bounded_revocable_and_tenant_scoped() -> None:
    admin = migration_engine()
    reset_tenant_data(admin)
    seed_tenant(admin, TENANT_A, ACTOR_A, "tenant-a")
    sessions = runtime_sessions()
    raw_token = "fixed-high-entropy-session-token-000000000001"
    store = PostgresSessionStore(
        sessions=sessions,
        pepper="fixed-pepper",
        session_id_factory=lambda: UUID("a0000000-0000-0000-0000-000000000001"),
        session_token_factory=lambda: raw_token,
        csrf_token_factory=lambda: "fixed-csrf-token",
    )
    credentials = store.create(owner_actor(), FIXED_NOW)
    assert credentials.raw_session_token == raw_token
    assert credentials.idle_expires_at == FIXED_NOW + timedelta(minutes=30)
    assert credentials.absolute_expires_at == FIXED_NOW + timedelta(hours=12)
    admin_sessions = build_session_factory(admin)
    with admin_sessions() as session, session.begin():
        set_request_context(session, TENANT_A, ACTOR_A)
        token_hash, csrf_hash = session.execute(
            text("SELECT token_hash, csrf_hash FROM auth_sessions")
        ).one()
        assert token_hash != raw_token
        assert csrf_hash != "fixed-csrf-token"

    resolved = store.resolve(raw_token, CORRELATION_A, FIXED_NOW + timedelta(minutes=5))
    assert resolved.tenant_id == TENANT_A
    assert resolved.actor_id == ACTOR_A
    assert resolved.roles == ("OWNER",)
    assert "tenant.manage" in resolved.permissions

    stored_hash = hash_session_token("fixed-csrf-token", "fixed-pepper")
    assert validate_csrf_and_origin(
        stored_csrf_hash=stored_hash,
        supplied_csrf_token="fixed-csrf-token",
        supplied_origin="https://app.example.test",
        allowed_origin="https://app.example.test",
        pepper="fixed-pepper",
    )
    with pytest.raises(AuthenticationRequired):
        store.resolve(raw_token + "tampered", CORRELATION_A, FIXED_NOW)
    with pytest.raises(AuthenticationRequired):
        store.resolve(raw_token, CORRELATION_A, FIXED_NOW + timedelta(hours=13))
    store.revoke(raw_token, ACTOR_A, FIXED_NOW + timedelta(minutes=6))
    with pytest.raises(AuthenticationRequired):
        store.resolve(raw_token, CORRELATION_A, FIXED_NOW + timedelta(minutes=7))


@pytest.mark.security
def test_tenant_and_membership_changes_fail_closed_and_revoke_sessions() -> None:
    admin = migration_engine()
    reset_tenant_data(admin)
    seed_tenant(admin, TENANT_A, ACTOR_A, "tenant-a")
    sessions = runtime_sessions()
    raw_token = "fixed-high-entropy-session-token-000000000002"
    store = PostgresSessionStore(
        sessions=sessions,
        pepper="fixed-pepper",
        session_id_factory=lambda: UUID("a0000000-0000-0000-0000-000000000002"),
        session_token_factory=lambda: raw_token,
        csrf_token_factory=lambda: "fixed-csrf-token-2",
    )
    store.create(owner_actor(), FIXED_NOW)
    admin_sessions = build_session_factory(admin)
    with admin_sessions() as session, session.begin():
        set_request_context(session, TENANT_A, ACTOR_A)
        session.execute(
            text("UPDATE tenants SET status = 'SUSPENDED', updated_at = :now WHERE id = :id"),
            {"now": FIXED_NOW + timedelta(minutes=1), "id": TENANT_A},
        )
    with pytest.raises(AuthenticationRequired):
        store.resolve(raw_token, CORRELATION_A, FIXED_NOW + timedelta(minutes=2))

    with admin_sessions() as session, session.begin():
        set_request_context(session, TENANT_A, ACTOR_A)
        session.execute(
            text("UPDATE tenants SET status = 'ACTIVE', updated_at = :now WHERE id = :id"),
            {"now": FIXED_NOW + timedelta(minutes=3), "id": TENANT_A},
        )
    with pytest.raises(AuthenticationRequired):
        store.resolve(raw_token, CORRELATION_A, FIXED_NOW + timedelta(minutes=3))
    with admin_sessions() as session, session.begin():
        set_request_context(session, TENANT_A, ACTOR_A)
        session.execute(
            text(
                """INSERT INTO user_roles (tenant_id, user_id, role_id, granted_by, granted_at)
                SELECT :tenant, :actor, id, :actor, :now FROM roles WHERE name = 'VIEWER'"""
            ),
            {"tenant": TENANT_A, "actor": ACTOR_A, "now": FIXED_NOW + timedelta(minutes=3)},
        )
        assert (
            session.execute(
                text("SELECT status FROM auth_sessions WHERE user_id = :actor"),
                {"actor": ACTOR_A},
            ).scalar_one()
            == "REVOKED"
        )
    with pytest.raises(AuthenticationRequired):
        store.resolve(raw_token, CORRELATION_A, FIXED_NOW + timedelta(minutes=4))

    permission_token = "fixed-high-entropy-session-token-000000000003"
    permission_store = PostgresSessionStore(
        sessions=sessions,
        pepper="fixed-pepper",
        session_id_factory=lambda: UUID("a0000000-0000-0000-0000-000000000003"),
        session_token_factory=lambda: permission_token,
        csrf_token_factory=lambda: "fixed-csrf-token-3",
    )
    permission_store.create(owner_actor(), FIXED_NOW + timedelta(minutes=5))
    with admin_sessions() as session, session.begin():
        set_request_context(session, TENANT_A, ACTOR_A)
        session.execute(
            text(
                """DELETE FROM role_permissions
                WHERE role_id = (SELECT id FROM roles WHERE name = 'VIEWER')
                  AND permission_id = (
                    SELECT id FROM permissions WHERE permission_key = 'tenant.read'
                  )"""
            )
        )
    with pytest.raises(AuthenticationRequired):
        permission_store.resolve(
            permission_token,
            CORRELATION_A,
            FIXED_NOW + timedelta(minutes=6),
        )


@pytest.mark.security
def test_runtime_sql_cannot_swap_or_extend_session_identity() -> None:
    admin = migration_engine()
    reset_tenant_data(admin)
    seed_tenant(admin, TENANT_A, ACTOR_A, "tenant-a")
    viewer_id = UUID("30000000-0000-0000-0000-000000000004")
    admin_sessions = build_session_factory(admin)
    with admin_sessions() as session, session.begin():
        set_request_context(session, TENANT_A, ACTOR_A)
        session.execute(
            text(
                """INSERT INTO users
                (id, tenant_id, external_subject, display_label, status, created_at, updated_at)
                VALUES (:id, :tenant, 'auth0|viewer', 'Viewer', 'ACTIVE', :now, :now)"""
            ),
            {"id": viewer_id, "tenant": TENANT_A, "now": FIXED_NOW},
        )
        session.execute(
            text(
                """INSERT INTO user_roles (tenant_id, user_id, role_id, granted_by, granted_at)
                SELECT :tenant, :viewer, id, :owner, :now FROM roles WHERE name = 'VIEWER'"""
            ),
            {"tenant": TENANT_A, "viewer": viewer_id, "owner": ACTOR_A, "now": FIXED_NOW},
        )
    viewer = ActorContext(
        tenant_id=TENANT_A,
        actor_id=viewer_id,
        subject="auth0|viewer",
        auth_method="auth0_oidc",
        roles=("VIEWER",),
        permissions=("tenant.read", "membership.read"),
        correlation_id=CORRELATION_A,
    )
    sessions = runtime_sessions()
    store = PostgresSessionStore(
        sessions=sessions,
        pepper="fixed-pepper",
        session_id_factory=lambda: UUID("a0000000-0000-0000-0000-000000000004"),
        session_token_factory=lambda: "viewer-session-token-000000000004",
        csrf_token_factory=lambda: "viewer-csrf-token-4",
    )
    store.create(viewer, FIXED_NOW)
    with pytest.raises(DBAPIError):
        with sessions() as session, session.begin():
            set_request_context(session, TENANT_A, viewer_id)
            session.execute(
                text("UPDATE auth_sessions SET user_id = :owner WHERE user_id = :viewer"),
                {"owner": ACTOR_A, "viewer": viewer_id},
            )
    with pytest.raises(DBAPIError):
        with sessions() as session, session.begin():
            set_request_context(session, TENANT_A, viewer_id)
            session.execute(
                text(
                    """UPDATE auth_sessions
                    SET absolute_expires_at = absolute_expires_at + interval '1 day'
                    WHERE user_id = :viewer"""
                ),
                {"viewer": viewer_id},
            )
    with pytest.raises(DBAPIError):
        with sessions() as session, session.begin():
            set_request_context(session, TENANT_A, viewer_id)
            session.execute(
                text(
                    """UPDATE auth_sessions SET idle_expires_at = absolute_expires_at
                    WHERE user_id = :viewer"""
                ),
                {"viewer": viewer_id},
            )
    resolved = store.resolve("viewer-session-token-000000000004", CORRELATION_A, FIXED_NOW)
    assert resolved.roles == ("VIEWER",)
