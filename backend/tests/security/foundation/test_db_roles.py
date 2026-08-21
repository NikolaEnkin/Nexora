import pytest
from backend.tests.integration.foundation.support import (
    ACTOR_A,
    TENANT_A,
    migration_engine,
    reset_tenant_data,
    seed_tenant,
)
from sqlalchemy import create_engine, text
from sqlalchemy.exc import DBAPIError

from app.config import get_settings


@pytest.mark.security
def test_runtime_roles_are_least_privilege() -> None:
    admin = migration_engine()
    reset_tenant_data(admin)
    seed_tenant(admin, TENANT_A, ACTOR_A, "tenant-a")
    with admin.connect() as connection:
        attrs = connection.execute(
            text(
                """SELECT rolsuper, rolcreaterole, rolcreatedb, rolbypassrls
                FROM pg_roles WHERE rolname = 'nexora_runtime'"""
            )
        ).one()
        assert tuple(attrs) == (False, False, False, False)
        owners = connection.execute(
            text(
                """SELECT count(*) FROM pg_class c JOIN pg_roles r ON r.oid = c.relowner
                WHERE r.rolname = 'nexora_runtime' AND c.relkind IN ('r', 'p')"""
            )
        ).scalar_one()
        assert owners == 0
        guard = connection.execute(
            text(
                """SELECT rolcanlogin, rolsuper, rolcreaterole, rolcreatedb, rolbypassrls
                FROM pg_roles WHERE rolname = 'nexora_rls_guard'"""
            )
        ).one()
        assert tuple(guard) == (False, False, False, False, True)
        grants = {
            tuple(row)
            for row in connection.execute(
                text(
                    """SELECT table_name, privilege_type
                    FROM information_schema.role_table_grants
                    WHERE grantee = 'nexora_runtime' AND table_schema = 'public'"""
                )
            ).all()
        }
        # Phase 03 (A-5) added the approval grants; Phase 04 (A-3) adds `clients`. The
        # assertion stays an exact match — it is extended, never relaxed — and
        # `DELETE` remains absent from every entry, on Phase-01 and Phase-03
        # tables alike.
        assert all(privilege != "DELETE" for _, privilege in grants)
        assert grants == {
            ("clients", "INSERT"),
            ("clients", "SELECT"),
            ("clients", "UPDATE"),
            ("approval_consumptions", "INSERT"),
            ("approval_consumptions", "SELECT"),
            ("approval_decisions", "INSERT"),
            ("approval_decisions", "SELECT"),
            ("approval_requests", "INSERT"),
            ("approval_requests", "SELECT"),
            ("approval_requests", "UPDATE"),
            ("policy_action_catalogue", "SELECT"),
            ("protected_effect_counters", "INSERT"),
            ("protected_effect_counters", "SELECT"),
            ("protected_effect_counters", "UPDATE"),
            ("audit_events", "INSERT"),
            ("audit_events", "SELECT"),
            ("auth_sessions", "INSERT"),
            ("auth_sessions", "SELECT"),
            ("auth_sessions", "UPDATE"),
            ("domain_events", "INSERT"),
            ("domain_events", "SELECT"),
            ("foundation_mutations", "INSERT"),
            ("foundation_mutations", "SELECT"),
            ("idempotency_records", "INSERT"),
            ("idempotency_records", "SELECT"),
            ("idempotency_records", "UPDATE"),
            ("outbox_events", "INSERT"),
            ("outbox_events", "SELECT"),
            ("outbox_events", "UPDATE"),
            ("permissions", "SELECT"),
            ("role_permissions", "SELECT"),
            ("roles", "SELECT"),
            ("tenants", "SELECT"),
            ("user_roles", "SELECT"),
            ("users", "SELECT"),
        }

    runtime = create_engine(get_settings().database_url)
    with runtime.connect() as connection:
        transaction = connection.begin()
        connection.execute(
            text(
                "SELECT set_config('app.tenant_id', :tenant, true), "
                "set_config('app.actor_id', :actor, true)"
            ),
            {"tenant": str(TENANT_A), "actor": str(ACTOR_A)},
        )
        with pytest.raises(DBAPIError):
            connection.execute(text("ALTER TABLE users DISABLE ROW LEVEL SECURITY"))
        transaction.rollback()
    with runtime.connect() as connection:
        transaction = connection.begin()
        with pytest.raises(DBAPIError):
            connection.execute(text("CREATE TABLE runtime_escape (id integer)"))
        transaction.rollback()
    with runtime.connect() as connection:
        transaction = connection.begin()
        with pytest.raises(DBAPIError):
            connection.execute(text("SELECT secret_value FROM nexora_private.rls_context_secrets"))
        transaction.rollback()
    with runtime.connect() as connection:
        transaction = connection.begin()
        with pytest.raises(DBAPIError):
            connection.execute(
                text(
                    """INSERT INTO permissions
                    (id, permission_key, description, contract_version, created_at)
                    VALUES ('10000000-0000-0000-0000-000000000099', 'admin.all',
                            'escalation', 1, CURRENT_TIMESTAMP)"""
                )
            )
        transaction.rollback()
    with runtime.connect() as connection:
        transaction = connection.begin()
        set_request_context_for_connection = text(
            "SELECT set_config('app.tenant_id', :tenant, true), "
            "set_config('app.actor_id', :actor, true)"
        )
        connection.execute(
            set_request_context_for_connection,
            {"tenant": str(TENANT_A), "actor": str(ACTOR_A)},
        )
        with pytest.raises(DBAPIError):
            connection.execute(text("DELETE FROM audit_events"))
        transaction.rollback()
