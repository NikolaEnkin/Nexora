"""The database half of the approval boundary.

These assertions exist because a service-side rule is only as good as what the
database will still refuse when the service is wrong. Each one is stated in
`ADR-004` or the packet as a *database* property, so each is asserted directly
against PostgreSQL rather than through the code under test.
"""

from uuid import UUID, uuid4

import pytest
from sqlalchemy import text

from app.db import set_request_context
from tests.integration.approvals.support import (
    CFO_ID,
    OWNER_ID,
    SECOND_DEPUTY_ID,
    build_harness,
    operator,
)
from tests.integration.foundation.support import FIXED_NOW, TENANT_A

pytestmark = pytest.mark.security

APPROVAL_TABLES = (
    "approval_requests",
    "approval_decisions",
    "approval_consumptions",
    "protected_effect_counters",
)


def test_a_tenant_may_have_at_most_one_active_deputy() -> None:
    """`ADR-004` §2 — "only one person" is a property of the schema."""
    harness = build_harness()
    engine = harness._engine
    assert engine is not None

    with engine.begin() as connection:
        _seed_context(connection)
        connection.execute(
            text(
                """INSERT INTO users (id, tenant_id, external_subject, display_label, status,
                                      created_at, updated_at)
                VALUES (:id, :tenant_id, 'auth0|second-deputy', 'second deputy', 'ACTIVE',
                        :now, :now)
                ON CONFLICT DO NOTHING"""
            ),
            {"id": SECOND_DEPUTY_ID, "tenant_id": TENANT_A, "now": FIXED_NOW},
        )

    with pytest.raises(Exception, match="at most one active DEPUTY"):
        with engine.begin() as connection:
            _seed_context(connection)
            connection.execute(
                text(
                    """INSERT INTO user_roles (tenant_id, user_id, role_id, granted_by, granted_at)
                    SELECT :tenant_id, :user_id, r.id, :granted_by, :now
                    FROM roles r WHERE r.tenant_id = :tenant_id AND r.name = 'DEPUTY'"""
                ),
                {
                    "tenant_id": TENANT_A,
                    "user_id": SECOND_DEPUTY_ID,
                    "granted_by": OWNER_ID,
                    "now": FIXED_NOW,
                },
            )

    # The original deputy is untouched.
    assert _active_deputy_ids(engine) == [CFO_ID]


def test_the_runtime_role_holds_no_delete_on_any_approval_table() -> None:
    """`ADR-004` §Rollback — approval history is never hard-deleted."""
    harness = build_harness()
    engine = harness._engine
    assert engine is not None
    with engine.begin() as connection:
        rows = connection.execute(
            text(
                """SELECT table_name, privilege_type FROM information_schema.role_table_grants
                WHERE grantee = 'nexora_runtime' AND table_name = ANY(:tables)
                  AND privilege_type = 'DELETE'"""
            ),
            {"tables": [*APPROVAL_TABLES, "policy_action_catalogue"]},
        ).all()
    assert rows == []


def test_the_runtime_role_cannot_update_approval_history() -> None:
    """Decisions and consumptions are append-only at the grant level, not only by trigger."""
    harness = build_harness()
    engine = harness._engine
    assert engine is not None
    with engine.begin() as connection:
        rows = connection.execute(
            text(
                """SELECT table_name, privilege_type FROM information_schema.role_table_grants
                WHERE grantee = 'nexora_runtime'
                  AND table_name IN ('approval_decisions', 'approval_consumptions')
                  AND privilege_type = 'UPDATE'"""
            )
        ).all()
    assert rows == []


def test_every_approval_table_forces_row_level_security() -> None:
    harness = build_harness()
    engine = harness._engine
    assert engine is not None
    with engine.begin() as connection:
        rows = connection.execute(
            text(
                """SELECT relname, relrowsecurity, relforcerowsecurity FROM pg_class
                WHERE relnamespace = 'public'::regnamespace AND relname = ANY(:tables)
                ORDER BY relname"""
            ),
            {"tables": list(APPROVAL_TABLES)},
        ).all()
    assert len(rows) == len(APPROVAL_TABLES)
    assert all(enabled and forced for _, enabled, forced in rows)


def test_a_decision_row_cannot_be_rewritten() -> None:
    """The append-only trigger refuses an UPDATE even from the table owner.

    A decision must exist first: a row-level trigger on an empty table fires zero
    times, which would have made this assertion vacuous.
    """
    from app.approvals.errors import ApprovalRequired
    from app.policy.canonical import payload_hash
    from tests.integration.approvals.support import client_create_descriptor, decide_all

    harness = build_harness()
    engine = harness._engine
    assert engine is not None
    descriptor = client_create_descriptor(key="append-only")
    with pytest.raises(ApprovalRequired) as pending:
        harness.gate.execute(actor=operator(1), descriptor=descriptor)
    approval_id = UUID(pending.value.details["approval_id"])
    decide_all(harness, approval_id, payload_hash(descriptor.normalized_arguments), (operator(2),))
    assert len(harness.repository.decisions_for(actor=operator(1), approval_id=approval_id)) == 1

    with pytest.raises(Exception, match="append-only"):
        with engine.begin() as connection:
            _seed_context(connection)
            connection.execute(
                text("UPDATE approval_decisions SET decision = 'REJECTED' WHERE true")
            )

    with pytest.raises(Exception, match="append-only"):
        with engine.begin() as connection:
            _seed_context(connection)
            connection.execute(text("DELETE FROM approval_decisions WHERE true"))


def test_an_approval_payload_cannot_drift_after_creation() -> None:
    """The immutability trigger protects what the approver actually saw."""
    from app.approvals.errors import ApprovalRequired
    from tests.integration.approvals.support import client_create_descriptor

    harness = build_harness()
    engine = harness._engine
    assert engine is not None
    with pytest.raises(ApprovalRequired) as pending:
        harness.gate.execute(actor=operator(1), descriptor=client_create_descriptor())
    approval_id = UUID(pending.value.details["approval_id"])

    with pytest.raises(Exception, match="immutable"):
        with engine.begin() as connection:
            _seed_context(connection)
            connection.execute(
                text("UPDATE approval_requests SET payload_hash = :hash WHERE id = :id"),
                {"hash": "f" * 64, "id": approval_id},
            )


def test_another_tenant_cannot_see_an_approval() -> None:
    """Row-level security is the boundary even with a correct identifier."""
    from app.approvals.errors import ApprovalRequired
    from tests.integration.approvals.support import client_create_descriptor

    harness = build_harness()
    requester = operator(1)
    with pytest.raises(ApprovalRequired) as pending:
        harness.gate.execute(actor=requester, descriptor=client_create_descriptor())
    approval_id = UUID(pending.value.details["approval_id"])

    foreign = requester.model_copy(update={"tenant_id": uuid4(), "actor_id": uuid4()})
    with harness.sessions() as session, session.begin():
        set_request_context(session, foreign.tenant_id, foreign.actor_id)
        found = session.execute(
            text("SELECT count(*) FROM approval_requests WHERE id = :id"), {"id": approval_id}
        ).scalar_one()
    assert found == 0


def test_the_seeded_catalogue_matches_the_code_catalogue() -> None:
    """Drift between migration `0003` and `app.policy.catalogue` is a defect in one of them."""
    from app.policy.catalogue import CATALOGUE, CATALOGUE_VERSION

    harness = build_harness()
    engine = harness._engine
    assert engine is not None
    with engine.begin() as connection:
        rows = connection.execute(
            text(
                """SELECT action_key, risk, required_permission, required_assurance
                FROM policy_action_catalogue WHERE catalogue_version = :version"""
            ),
            {"version": CATALOGUE_VERSION},
        ).all()

    stored = {row[0]: (row[1], row[2], row[3]) for row in rows}
    expected = {
        key: (entry.risk.value, entry.required_permission, entry.required_assurance.value)
        for key, entry in CATALOGUE.items()
    }
    assert stored == expected


def test_the_migration_seeds_role_permissions_for_an_existing_tenant() -> None:
    """Re-run `0003` against a database that already has a tenant.

    The first version of this migration recorded a *role* id in
    `role_permissions.granted_by`, which the `fk_role_permissions_grantor` foreign
    key forbids. It passed anyway, because the migration only ever ran against a
    database with no tenants and therefore inserted no rows. Exercising the
    seeding path with a tenant present is what makes this assertion meaningful.
    """
    harness = build_harness()
    engine = harness._engine
    assert engine is not None

    environment = {"NEXORA_ENVIRONMENT": "test", "NEXORA_ALLOW_DESTRUCTIVE_MIGRATION_CHECK": "true"}
    _alembic(["downgrade", "-1"], environment)
    _alembic(["upgrade", "head"], environment)

    with engine.begin() as connection:
        _seed_context(connection)
        granted = connection.execute(
            text(
                """SELECT r.name, p.permission_key
                FROM role_permissions rp
                JOIN roles r ON r.id = rp.role_id
                JOIN permissions p ON p.id = rp.permission_id
                WHERE p.permission_key LIKE 'approval.%'
                ORDER BY r.name, p.permission_key"""
            )
        ).all()
        grantors_are_users = connection.execute(
            text(
                """SELECT count(*) FROM role_permissions rp
                WHERE NOT EXISTS (SELECT 1 FROM users u WHERE u.id = rp.granted_by)"""
            )
        ).scalar_one()

    pairs = {(name, key) for name, key in granted}
    assert ("OWNER", "approval.decide") in pairs
    assert ("OPERATOR", "approval.decide") in pairs
    assert ("DEPUTY", "approval.decide.high") in pairs
    assert ("OPERATOR", "approval.decide.high") not in pairs
    assert grantors_are_users == 0


def _alembic(arguments: list[str], environment: dict[str, str]) -> None:
    import os
    import subprocess

    result = subprocess.run(  # noqa: S603
        [".venv/bin/alembic", "-c", "backend/alembic.ini", *arguments],
        capture_output=True,
        text=True,
        env={**os.environ, **environment},
        check=False,
    )
    if result.returncode != 0:
        raise AssertionError(f"alembic {' '.join(arguments)} failed:\n{result.stderr}")


def _seed_context(connection) -> None:  # type: ignore[no-untyped-def]
    from app.config import get_settings
    from app.db.engine import context_signature

    secret = get_settings().rls_context_secret.get_secret_value()
    connection.execute(
        text(
            "SELECT set_config('app.tenant_id', :tenant_id, true), "
            "set_config('app.actor_id', :actor_id, true), "
            "set_config('app.context_signature', :signature, true)"
        ),
        {
            "tenant_id": str(TENANT_A),
            "actor_id": str(OWNER_ID),
            "signature": context_signature(TENANT_A, OWNER_ID, secret),
        },
    )


def _active_deputy_ids(engine) -> list[UUID]:  # type: ignore[no-untyped-def]
    with engine.begin() as connection:
        _seed_context(connection)
        return [
            row[0]
            for row in connection.execute(
                text(
                    """SELECT ur.user_id FROM user_roles ur
                    JOIN roles r ON r.id = ur.role_id
                    JOIN users u ON u.id = ur.user_id
                    WHERE r.name = 'DEPUTY' AND u.status = 'ACTIVE'
                    ORDER BY ur.user_id"""
                )
            ).all()
        ]
