from concurrent.futures import ThreadPoolExecutor
from uuid import UUID

import pytest
from backend.tests.integration.foundation.support import (
    ACTOR_A,
    CORRELATION_A,
    FIXED_NOW,
    TENANT_A,
    migration_engine,
    reset_tenant_data,
    seed_tenant,
)
from sqlalchemy import text
from sqlalchemy.exc import DBAPIError

from app.config import get_settings
from app.db import build_session_factory, set_request_context
from app.errors import IdempotencyConflict
from app.identity import TenantProvisioner


@pytest.mark.security
def test_controlled_provisioning_and_foundation_invariants() -> None:
    engine = migration_engine()
    reset_tenant_data(engine)
    sessions = build_session_factory(engine)
    disabled = TenantProvisioner(
        migration_sessions=sessions,
        context_secret=get_settings().rls_context_secret.get_secret_value(),
        enabled=False,
    )
    with pytest.raises(RuntimeError, match="disabled"):
        disabled.provision(
            tenant_id=TENANT_A,
            slug="tenant-a",
            owner_id=ACTOR_A,
            owner_subject="auth0|tenant-a-owner",
            owner_label="Tenant A owner",
            correlation_id=CORRELATION_A,
            idempotency_key="disabled-provision",
            now=FIXED_NOW,
        )

    seed_tenant(engine, TENANT_A, ACTOR_A, "tenant-a", retain_provisioning_evidence=True)
    provisioner = TenantProvisioner(
        migration_sessions=sessions,
        context_secret=get_settings().rls_context_secret.get_secret_value(),
        enabled=True,
    )
    replay = provisioner.provision(
        tenant_id=TENANT_A,
        slug="tenant-a",
        owner_id=ACTOR_A,
        owner_subject="auth0|tenant-a-owner",
        owner_label="tenant-a owner",
        correlation_id=CORRELATION_A,
        idempotency_key="fixture-provision-tenant-a",
        now=FIXED_NOW,
    )
    assert replay.replayed is True
    with pytest.raises(IdempotencyConflict):
        provisioner.provision(
            tenant_id=TENANT_A,
            slug="tenant-a-changed",
            owner_id=ACTOR_A,
            owner_subject="auth0|tenant-a-owner",
            owner_label="tenant-a owner",
            correlation_id=CORRELATION_A,
            idempotency_key="fixture-provision-tenant-a",
            now=FIXED_NOW,
        )
    with sessions() as session, session.begin():
        set_request_context(session, TENANT_A, ACTOR_A)
        # Phase 03 (amendment A-6, finding F-01) adds DEPUTY to provisioning, so a
        # tenant created after migration 0003 has somebody who may approve. The
        # assertion stays exact — extended, never relaxed.
        assert session.execute(text("SELECT name FROM roles ORDER BY name")).scalars().all() == [
            "DEPUTY",
            "OPERATOR",
            "OWNER",
            "VIEWER",
        ]
        mappings = session.execute(
            text(
                """SELECT roles.name, permissions.permission_key FROM role_permissions
                JOIN roles ON roles.tenant_id = role_permissions.tenant_id
                          AND roles.id = role_permissions.role_id
                JOIN permissions ON permissions.id = role_permissions.permission_id
                ORDER BY roles.name, permissions.permission_key"""
            )
        ).all()
        # 16 = OWNER 7 + OPERATOR 3 + VIEWER 2 + DEPUTY 4 (amendment A-6).
        assert len(mappings) == 16
        by_role: dict[str, set[str]] = {}
        for role_name, permission_key in mappings:
            by_role.setdefault(role_name, set()).add(permission_key)
        # DEPUTY carries approval authority and nothing administrative (ADR-004 §2).
        assert "approval.decide.high" in by_role["DEPUTY"]
        assert "tenant.manage" not in by_role["DEPUTY"]
        assert "membership.manage" not in by_role["DEPUTY"]
        # A VIEWER may still approve nothing.
        assert not any(key.startswith("approval.") for key in by_role["VIEWER"])
        for table in (
            "foundation_mutations",
            "domain_events",
            "outbox_events",
            "idempotency_records",
            "audit_events",
        ):
            assert session.execute(text(f"SELECT count(*) FROM {table}")).scalar_one() == 1

    with pytest.raises(DBAPIError, match="immutable foundation field"):
        with sessions() as session, session.begin():
            set_request_context(session, TENANT_A, ACTOR_A)
            session.execute(
                text("UPDATE tenants SET slug = 'changed' WHERE id = :id"),
                {"id": TENANT_A},
            )

    with pytest.raises(DBAPIError, match="retain an active OWNER"):
        with sessions() as session, session.begin():
            set_request_context(session, TENANT_A, ACTOR_A)
            session.execute(
                text(
                    """DELETE FROM user_roles WHERE tenant_id = :tenant AND user_id = :actor
                    AND role_id = (SELECT id FROM roles WHERE name = 'OWNER')"""
                ),
                {"tenant": TENANT_A, "actor": ACTOR_A},
            )


@pytest.mark.security
def test_concurrent_owner_removal_preserves_exactly_one_owner() -> None:
    engine = migration_engine()
    reset_tenant_data(engine)
    seed_tenant(engine, TENANT_A, ACTOR_A, "tenant-a")
    second_owner = UUID("30000000-0000-0000-0000-000000000003")
    sessions = build_session_factory(engine)
    with sessions() as session, session.begin():
        set_request_context(session, TENANT_A, ACTOR_A)
        session.execute(
            text(
                """INSERT INTO users
                (id, tenant_id, external_subject, display_label, status, created_at, updated_at)
                VALUES (:id, :tenant, 'auth0|second-owner', 'Second owner', 'ACTIVE', :now, :now)"""
            ),
            {"id": second_owner, "tenant": TENANT_A, "now": FIXED_NOW},
        )
        session.execute(
            text(
                """INSERT INTO user_roles (tenant_id, user_id, role_id, granted_by, granted_at)
                SELECT :tenant, :user, id, :grantor, :now FROM roles WHERE name = 'OWNER'"""
            ),
            {
                "tenant": TENANT_A,
                "user": second_owner,
                "grantor": ACTOR_A,
                "now": FIXED_NOW,
            },
        )

    def remove_owner(actor_id: UUID) -> bool:
        try:
            with sessions() as session, session.begin():
                set_request_context(session, TENANT_A, actor_id)
                session.execute(
                    text(
                        """DELETE FROM user_roles WHERE tenant_id = :tenant AND user_id = :user
                        AND role_id = (SELECT id FROM roles WHERE name = 'OWNER')"""
                    ),
                    {"tenant": TENANT_A, "user": actor_id},
                )
            return True
        except DBAPIError:
            return False

    with ThreadPoolExecutor(max_workers=2) as executor:
        outcomes = list(executor.map(remove_owner, (ACTOR_A, second_owner)))
    assert sorted(outcomes) == [False, True]
    with sessions() as session, session.begin():
        set_request_context(session, TENANT_A, ACTOR_A)
        remaining = session.execute(
            text(
                """SELECT count(*) FROM user_roles JOIN roles
                ON roles.tenant_id = user_roles.tenant_id AND roles.id = user_roles.role_id
                WHERE roles.name = 'OWNER'"""
            )
        ).scalar_one()
        assert remaining == 1


@pytest.mark.security
def test_concurrent_first_provisioning_replays_one_durable_result() -> None:
    engine = migration_engine()
    reset_tenant_data(engine)
    provisioner = TenantProvisioner(
        migration_sessions=build_session_factory(engine),
        context_secret=get_settings().rls_context_secret.get_secret_value(),
        enabled=True,
    )

    def provision_once() -> bool:
        return provisioner.provision(
            tenant_id=TENANT_A,
            slug="tenant-a",
            owner_id=ACTOR_A,
            owner_subject="auth0|tenant-a-owner",
            owner_label="tenant-a owner",
            correlation_id=CORRELATION_A,
            idempotency_key="concurrent-first-provision",
            now=FIXED_NOW,
        ).replayed

    with ThreadPoolExecutor(max_workers=2) as executor:
        replayed = list(executor.map(lambda _: provision_once(), range(2)))
    assert sorted(replayed) == [False, True]
    sessions = build_session_factory(engine)
    with sessions() as session, session.begin():
        set_request_context(session, TENANT_A, ACTOR_A)
        assert session.execute(text("SELECT count(*) FROM tenants")).scalar_one() == 1
        for table in (
            "foundation_mutations",
            "domain_events",
            "outbox_events",
            "idempotency_records",
            "audit_events",
        ):
            assert session.execute(text(f"SELECT count(*) FROM {table}")).scalar_one() == 1
