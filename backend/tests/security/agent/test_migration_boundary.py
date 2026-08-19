"""The database boundary around the Phase-02 runtime schema.

These assert the properties the runtime *cannot* violate even if application code
is wrong: least-privilege grants with no DELETE anywhere, forced row-level
security, an append-only event ledger, immutable checkpoints, and a state machine
whose terminal states are terminal in PostgreSQL rather than only in Python.
"""

import importlib.util
from pathlib import Path
from types import ModuleType
from uuid import UUID

import pytest
from backend.tests.integration.agent.support import (
    ACTOR_A,
    ACTOR_B,
    FIXED_NOW,
    TENANT_A,
    TENANT_B,
    insert_operation,
    migration_engine,
    reset_agent_data,
    runtime_sessions,
    seed_both_tenants,
)
from sqlalchemy import text
from sqlalchemy.exc import DBAPIError

from app.db import set_request_context

AGENT_TABLES = (
    "agent_operations",
    "agent_operation_events",
    "agent_checkpoints",
    "agent_checkpoint_writes",
)
MIGRATION_PATH = Path("backend/alembic/versions/0002_langgraph_checkpoint.py")


def _migration_module() -> ModuleType:
    """Load revision 0002 by path; alembic version modules are not importable by name."""
    spec = importlib.util.spec_from_file_location("phase02_migration", MIGRATION_PATH)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@pytest.fixture
def prepared() -> None:
    admin = migration_engine()
    seed_both_tenants(admin)
    reset_agent_data(admin)


@pytest.mark.security
def test_agent_schema_grants_are_least_privilege(prepared: None) -> None:
    admin = migration_engine()
    with admin.connect() as connection:
        grants = {
            tuple(row)
            for row in connection.execute(
                text(
                    """SELECT table_name, privilege_type
                    FROM information_schema.role_table_grants
                    WHERE grantee = 'nexora_runtime' AND table_schema = 'nexora_agent'"""
                )
            ).all()
        }
        assert grants == {
            ("agent_checkpoint_writes", "INSERT"),
            ("agent_checkpoint_writes", "SELECT"),
            ("agent_checkpoint_writes", "UPDATE"),
            ("agent_checkpoints", "INSERT"),
            ("agent_checkpoints", "SELECT"),
            ("agent_operation_events", "INSERT"),
            ("agent_operation_events", "SELECT"),
            ("agent_operations", "INSERT"),
            ("agent_operations", "SELECT"),
            ("agent_operations", "UPDATE"),
        }
        # No DELETE or TRUNCATE anywhere in the schema.
        assert not {item for item in grants if item[1] in {"DELETE", "TRUNCATE"}}

        rls = connection.execute(
            text(
                """SELECT relname, relrowsecurity, relforcerowsecurity, relowner::regrole::text
                FROM pg_class WHERE relnamespace = CAST('nexora_agent' AS regnamespace)
                  AND relname = ANY(:tables) ORDER BY relname"""
            ),
            {"tables": sorted(AGENT_TABLES)},
        ).all()
        assert len(rls) == len(AGENT_TABLES)
        for row in rls:
            assert row[1] is True, row[0]
            assert row[2] is True, row[0]
            assert row[3] == "nexora_migrator", row[0]

        # The runtime role owns nothing and PUBLIC reaches nothing.
        assert (
            connection.execute(
                text(
                    """SELECT count(*) FROM pg_class c JOIN pg_roles r ON r.oid = c.relowner
                    WHERE r.rolname = 'nexora_runtime' AND c.relkind IN ('r', 'p')"""
                )
            ).scalar_one()
            == 0
        )
        assert (
            connection.execute(
                text("SELECT has_schema_privilege('public', 'nexora_agent', 'USAGE')")
            ).scalar_one()
            is False
        )


@pytest.mark.security
def test_runtime_cannot_delete_or_create_in_the_agent_schema(prepared: None) -> None:
    sessions = runtime_sessions()
    with sessions() as session, session.begin():
        set_request_context(session, TENANT_A, ACTOR_A)
        insert_operation(
            session, tenant_id=TENANT_A, actor_id=ACTOR_A, client_request_id="boundary-delete"
        )

    for statement in (
        "DELETE FROM nexora_agent.agent_operations",
        "DELETE FROM nexora_agent.agent_operation_events",
        "DELETE FROM nexora_agent.agent_checkpoints",
        "DELETE FROM nexora_agent.agent_checkpoint_writes",
        "TRUNCATE TABLE nexora_agent.agent_operations",
        "CREATE TABLE nexora_agent.runtime_escape (id integer)",
        "ALTER TABLE nexora_agent.agent_operations DISABLE ROW LEVEL SECURITY",
    ):
        with sessions() as session:
            transaction = session.begin()
            set_request_context(session, TENANT_A, ACTOR_A)
            with pytest.raises(DBAPIError):
                session.execute(text(statement))
            transaction.rollback()

    # The row survived every attempt.
    with sessions() as session, session.begin():
        set_request_context(session, TENANT_A, ACTOR_A)
        assert (
            session.execute(text("SELECT count(*) FROM nexora_agent.agent_operations")).scalar_one()
            == 1
        )


@pytest.mark.security
def test_terminal_operation_cannot_reactivate(prepared: None) -> None:
    sessions = runtime_sessions()
    with sessions() as session, session.begin():
        set_request_context(session, TENANT_A, ACTOR_A)
        operation_id = insert_operation(
            session, tenant_id=TENANT_A, actor_id=ACTOR_A, client_request_id="boundary-terminal"
        )
        session.execute(
            text(
                """UPDATE nexora_agent.agent_operations
                SET state = 'RUNNING', updated_at = :now WHERE id = :id"""
            ),
            {"id": operation_id, "now": FIXED_NOW},
        )
        session.execute(
            text(
                """UPDATE nexora_agent.agent_operations
                SET state = 'COMPLETED', terminal_at = :now, updated_at = :now
                WHERE id = :id"""
            ),
            {"id": operation_id, "now": FIXED_NOW},
        )

    for forbidden_state in ("RUNNING", "RECEIVED", "WAITING", "FAILED"):
        with sessions() as session:
            transaction = session.begin()
            set_request_context(session, TENANT_A, ACTOR_A)
            with pytest.raises(DBAPIError):
                session.execute(
                    text(
                        """UPDATE nexora_agent.agent_operations
                        SET state = :state, updated_at = :now WHERE id = :id"""
                    ),
                    {"id": operation_id, "state": forbidden_state, "now": FIXED_NOW},
                )
            transaction.rollback()

    with sessions() as session, session.begin():
        set_request_context(session, TENANT_A, ACTOR_A)
        assert (
            session.execute(
                text("SELECT state FROM nexora_agent.agent_operations WHERE id = :id"),
                {"id": operation_id},
            ).scalar_one()
            == "COMPLETED"
        )


@pytest.mark.security
def test_checkpoint_sequence_cannot_move_backwards(prepared: None) -> None:
    sessions = runtime_sessions()
    with sessions() as session, session.begin():
        set_request_context(session, TENANT_A, ACTOR_A)
        operation_id = insert_operation(
            session,
            tenant_id=TENANT_A,
            actor_id=ACTOR_A,
            client_request_id="boundary-sequence",
            state="RUNNING",
            checkpoint_seq=5,
        )

    with sessions() as session:
        transaction = session.begin()
        set_request_context(session, TENANT_A, ACTOR_A)
        with pytest.raises(DBAPIError):
            session.execute(
                text(
                    """UPDATE nexora_agent.agent_operations
                    SET checkpoint_seq = 4, updated_at = :now WHERE id = :id"""
                ),
                {"id": operation_id, "now": FIXED_NOW},
            )
        transaction.rollback()


@pytest.mark.security
def test_operation_identity_is_unique_per_tenant_actor_and_request(prepared: None) -> None:
    sessions = runtime_sessions()
    with sessions() as session, session.begin():
        set_request_context(session, TENANT_A, ACTOR_A)
        insert_operation(
            session, tenant_id=TENANT_A, actor_id=ACTOR_A, client_request_id="duplicate-request"
        )

    with sessions() as session:
        transaction = session.begin()
        set_request_context(session, TENANT_A, ACTOR_A)
        with pytest.raises(DBAPIError):
            insert_operation(
                session, tenant_id=TENANT_A, actor_id=ACTOR_A, client_request_id="duplicate-request"
            )
        transaction.rollback()

    # The same client_request_id under a different tenant is a different operation.
    with sessions() as session, session.begin():
        set_request_context(session, TENANT_B, ACTOR_B)
        other = insert_operation(
            session, tenant_id=TENANT_B, actor_id=ACTOR_B, client_request_id="duplicate-request"
        )
        assert isinstance(other, UUID)


@pytest.mark.security
def test_foreign_tenant_sees_no_agent_row(prepared: None) -> None:
    sessions = runtime_sessions()
    with sessions() as session, session.begin():
        set_request_context(session, TENANT_A, ACTOR_A)
        insert_operation(
            session, tenant_id=TENANT_A, actor_id=ACTOR_A, client_request_id="isolation-a"
        )

    with sessions() as session, session.begin():
        set_request_context(session, TENANT_B, ACTOR_B)
        for table in AGENT_TABLES:
            count = session.execute(text(f"SELECT count(*) FROM nexora_agent.{table}")).scalar_one()
            assert count == 0, table

    # Tenant A still sees exactly its own row: the read above changed nothing.
    with sessions() as session, session.begin():
        set_request_context(session, TENANT_A, ACTOR_A)
        assert (
            session.execute(text("SELECT count(*) FROM nexora_agent.agent_operations")).scalar_one()
            == 1
        )


@pytest.mark.security
def test_missing_or_forged_context_yields_no_rows(prepared: None) -> None:
    sessions = runtime_sessions()
    with sessions() as session, session.begin():
        set_request_context(session, TENANT_A, ACTOR_A)
        insert_operation(
            session, tenant_id=TENANT_A, actor_id=ACTOR_A, client_request_id="isolation-context"
        )

    # No context at all.
    with sessions() as session, session.begin():
        assert (
            session.execute(text("SELECT count(*) FROM nexora_agent.agent_operations")).scalar_one()
            == 0
        )

    # Correct tenant and actor, but an unsigned context: the HMAC check fails closed.
    with sessions() as session, session.begin():
        session.execute(
            text(
                "SELECT set_config('app.tenant_id', :tenant, true), "
                "set_config('app.actor_id', :actor, true), "
                "set_config('app.context_signature', 'forged', true)"
            ),
            {"tenant": str(TENANT_A), "actor": str(ACTOR_A)},
        )
        assert (
            session.execute(text("SELECT count(*) FROM nexora_agent.agent_operations")).scalar_one()
            == 0
        )

    # Positive control: the row really is there, so the zeroes above are the RLS
    # boundary refusing rather than an insert that quietly did nothing.
    with sessions() as session, session.begin():
        set_request_context(session, TENANT_A, ACTOR_A)
        assert (
            session.execute(text("SELECT count(*) FROM nexora_agent.agent_operations")).scalar_one()
            == 1
        )


@pytest.mark.security
def test_downgrade_refuses_while_an_operation_is_active(
    prepared: None, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The guard must refuse rather than silently discard in-flight work."""
    migration = _migration_module()
    admin = migration_engine()
    sessions = runtime_sessions()

    monkeypatch.setenv("NEXORA_ENVIRONMENT", "test")
    monkeypatch.setenv("NEXORA_ALLOW_DESTRUCTIVE_MIGRATION_CHECK", "true")

    # With nothing running, a disposable downgrade is permitted.
    with admin.begin() as connection:
        assert migration.active_operation_count(connection) == 0
        migration.assert_downgrade_allowed(connection)

    with sessions() as session, session.begin():
        set_request_context(session, TENANT_A, ACTOR_A)
        insert_operation(
            session,
            tenant_id=TENANT_A,
            actor_id=ACTOR_A,
            client_request_id="downgrade-guard",
            state="RUNNING",
        )

    # The guard sees the row through FORCE RLS and refuses.
    with admin.begin() as connection:
        assert migration.active_operation_count(connection) == 1
        with pytest.raises(RuntimeError, match="operations are active"):
            migration.assert_downgrade_allowed(connection)

    # A terminal operation does not block a disposable downgrade.
    with sessions() as session, session.begin():
        set_request_context(session, TENANT_A, ACTOR_A)
        session.execute(
            text(
                """UPDATE nexora_agent.agent_operations
                SET state = 'CANCELLED', terminal_at = :now, updated_at = :now
                WHERE client_request_id = 'downgrade-guard'"""
            ),
            {"now": FIXED_NOW},
        )
    with admin.begin() as connection:
        assert migration.active_operation_count(connection) == 0
        migration.assert_downgrade_allowed(connection)


@pytest.mark.security
def test_downgrade_refuses_outside_a_disposable_environment(
    prepared: None, monkeypatch: pytest.MonkeyPatch
) -> None:
    migration = _migration_module()
    admin = migration_engine()

    monkeypatch.setenv("NEXORA_ALLOW_DESTRUCTIVE_MIGRATION_CHECK", "true")
    monkeypatch.setenv("NEXORA_ENVIRONMENT", "production")
    with admin.begin() as connection:
        with pytest.raises(RuntimeError, match="disposable"):
            migration.assert_downgrade_allowed(connection)

    monkeypatch.setenv("NEXORA_ENVIRONMENT", "test")
    monkeypatch.delenv("NEXORA_ALLOW_DESTRUCTIVE_MIGRATION_CHECK", raising=False)
    with admin.begin() as connection:
        with pytest.raises(RuntimeError, match="destructive opt-in"):
            migration.assert_downgrade_allowed(connection)
