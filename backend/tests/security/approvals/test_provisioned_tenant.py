"""Finding F-01 — a freshly provisioned tenant can actually complete an approval.

Migration `0003` backfills tenants that already exist. This covers the other half:
a tenant created *after* the migration, through the real `TenantProvisioner`.

The actors here are built from permissions **read out of the database**, not from
the hardcoded lists in `tests/integration/approvals/support.py`. That distinction
is the whole point of the test. F-01 stayed invisible precisely because the other
suites supply `ActorContext.permissions` directly, so they would keep passing even
if no role in the database mapped `approval.decide` to anyone.
"""

from uuid import UUID, uuid4

import pytest
from sqlalchemy import text

from app.approvals.audit import ApprovalAuditLog
from app.approvals.contracts import ApprovalStatus, DecisionType
from app.approvals.errors import ApprovalRequired
from app.approvals.gate import GateOutcome, ProtectedActionGate
from app.approvals.repository import ApprovalRepository
from app.approvals.service import ApprovalService
from app.config import get_settings
from app.contracts import ActorContext
from app.db import build_session_factory, set_request_context
from app.identity import TenantProvisioner
from app.policy.canonical import payload_hash
from app.rate_limit import InMemoryRateLimiter
from tests.integration.approvals.support import (
    MutableClock,
    invoice_issue_descriptor,
)
from tests.integration.foundation.support import (
    FIXED_NOW,
    migration_engine,
    reset_tenant_data,
    runtime_sessions,
)

pytestmark = pytest.mark.security

NEW_TENANT = UUID("20000000-0000-0000-0000-0000000000f1")
NEW_OWNER = UUID("30000000-0000-0000-0000-0000000000f1")
NEW_DEPUTY = UUID("30000000-0000-0000-0000-0000000000f2")
NEW_OPERATOR = UUID("30000000-0000-0000-0000-0000000000f3")
CORRELATION = UUID("90000000-0000-0000-0000-0000000000f1")


def _provision_fresh_tenant():  # type: ignore[no-untyped-def]
    engine = migration_engine()
    reset_tenant_data(engine)
    settings = get_settings()
    TenantProvisioner(
        migration_sessions=build_session_factory(engine),
        context_secret=settings.rls_context_secret.get_secret_value(),
        enabled=True,
    ).provision(
        tenant_id=NEW_TENANT,
        slug="fresh",
        owner_id=NEW_OWNER,
        owner_subject="auth0|fresh-owner",
        owner_label="fresh owner",
        correlation_id=CORRELATION,
        idempotency_key="fresh-provision",
        now=FIXED_NOW,
    )
    return engine


def _permissions_for_role(engine, role_name: str) -> tuple[str, ...]:
    """Read the role's permissions from the database, as a real boundary would."""
    with engine.begin() as connection:
        _context(connection)
        rows = (
            connection.execute(
                text(
                    """SELECT p.permission_key
                FROM role_permissions rp
                JOIN roles r ON r.id = rp.role_id
                JOIN permissions p ON p.id = rp.permission_id
                WHERE r.tenant_id = :tenant_id AND r.name = :role
                ORDER BY p.permission_key"""
                ),
                {"tenant_id": NEW_TENANT, "role": role_name},
            )
            .scalars()
            .all()
        )
    return tuple(rows)


def _context(connection) -> None:  # type: ignore[no-untyped-def]
    from app.db.engine import context_signature

    secret = get_settings().rls_context_secret.get_secret_value()
    connection.execute(
        text(
            "SELECT set_config('app.tenant_id', :tenant_id, true), "
            "set_config('app.actor_id', :actor_id, true), "
            "set_config('app.context_signature', :signature, true)"
        ),
        {
            "tenant_id": str(NEW_TENANT),
            "actor_id": str(NEW_OWNER),
            "signature": context_signature(NEW_TENANT, NEW_OWNER, secret),
        },
    )


def _add_member(engine, user_id: UUID, label: str, role_name: str) -> None:
    with engine.begin() as connection:
        _context(connection)
        connection.execute(
            text(
                """INSERT INTO users (id, tenant_id, external_subject, display_label, status,
                                      created_at, updated_at)
                VALUES (:id, :tenant_id, :subject, :label, 'ACTIVE', :now, :now)
                ON CONFLICT DO NOTHING"""
            ),
            {
                "id": user_id,
                "tenant_id": NEW_TENANT,
                "subject": f"auth0|{label}",
                "label": label,
                "now": FIXED_NOW,
            },
        )
        connection.execute(
            text(
                """INSERT INTO user_roles (tenant_id, user_id, role_id, granted_by, granted_at)
                SELECT :tenant_id, :user_id, r.id, :granted_by, :now
                FROM roles r WHERE r.tenant_id = :tenant_id AND r.name = :role"""
            ),
            {
                "tenant_id": NEW_TENANT,
                "user_id": user_id,
                "granted_by": NEW_OWNER,
                "now": FIXED_NOW,
                "role": role_name,
            },
        )


def _actor(actor_id: UUID, roles: tuple[str, ...], permissions: tuple[str, ...]) -> ActorContext:
    return ActorContext(
        tenant_id=NEW_TENANT,
        actor_id=actor_id,
        subject=f"auth0|{actor_id}",
        auth_method="test_fixture",
        assurance="step_up",
        roles=roles,
        permissions=permissions,
        correlation_id=CORRELATION,
    )


def test_provisioning_creates_the_deputy_role_and_approval_permissions() -> None:
    engine = _provision_fresh_tenant()

    with engine.begin() as connection:
        _context(connection)
        role_names = set(
            connection.execute(
                text("SELECT name FROM roles WHERE tenant_id = :t"), {"t": NEW_TENANT}
            ).scalars()
        )
    assert role_names == {"OWNER", "OPERATOR", "VIEWER", "DEPUTY"}

    assert "approval.decide" in _permissions_for_role(engine, "OPERATOR")
    assert "approval.decide.high" in _permissions_for_role(engine, "DEPUTY")
    assert "approval.decide.high" in _permissions_for_role(engine, "OWNER")
    # A VIEWER may still approve nothing.
    assert "approval.decide" not in _permissions_for_role(engine, "VIEWER")
    # DEPUTY carries approval authority and nothing administrative.
    deputy = _permissions_for_role(engine, "DEPUTY")
    assert "tenant.manage" not in deputy
    assert "membership.manage" not in deputy


def test_a_freshly_provisioned_tenant_can_complete_an_r3_approval() -> None:
    """End to end, with every permission sourced from the database."""
    engine = _provision_fresh_tenant()
    _add_member(engine, NEW_DEPUTY, "fresh-cfo", "DEPUTY")
    _add_member(engine, NEW_OPERATOR, "fresh-operator", "OPERATOR")

    business = ("invoice.issue", "payment.record")
    requester = _actor(
        NEW_OPERATOR,
        ("OPERATOR",),
        (*_permissions_for_role(engine, "OPERATOR"), *business),
    )
    approver = _actor(
        NEW_DEPUTY,
        ("DEPUTY",),
        (*_permissions_for_role(engine, "DEPUTY"), *business),
    )

    sessions = runtime_sessions()
    clock = MutableClock()
    repository = ApprovalRepository(sessions=sessions)
    service = ApprovalService(
        repository=repository, audit=ApprovalAuditLog(sessions=sessions), clock=clock
    )
    gate = ProtectedActionGate(
        approvals=service,
        repository=repository,
        limiter=InMemoryRateLimiter(clock=clock),
        audit=service.audit,
        clock=clock,
    )

    descriptor = invoice_issue_descriptor(amount="500.00", key="fresh-tenant-1")
    with pytest.raises(ApprovalRequired) as pending:
        gate.execute(actor=requester, descriptor=descriptor)
    approval_id = UUID(pending.value.details["approval_id"])

    # Path 3: one DEPUTY decision for a small OPERATOR request.
    service.decide(
        actor=approver,
        approval_id=approval_id,
        decision=DecisionType.APPROVED,
        payload_hash=payload_hash(descriptor.normalized_arguments),
        idempotency_key="fresh-decide-1",
    )

    result = gate.execute(actor=requester, descriptor=descriptor)
    assert result.outcome is GateOutcome.EXECUTED
    assert result.approval is not None
    assert result.approval.status is ApprovalStatus.CONSUMED

    with sessions() as session, session.begin():
        set_request_context(session, NEW_TENANT, NEW_OPERATOR)
        effects = session.execute(
            text("SELECT COALESCE(sum(effect_count), 0) FROM protected_effect_counters")
        ).scalar_one()
    assert effects == 1


def test_the_single_deputy_constraint_holds_in_a_fresh_tenant() -> None:
    engine = _provision_fresh_tenant()
    _add_member(engine, NEW_DEPUTY, "fresh-cfo", "DEPUTY")

    with pytest.raises(Exception, match="at most one active DEPUTY"):
        _add_member(engine, uuid4(), "second-deputy", "DEPUTY")
