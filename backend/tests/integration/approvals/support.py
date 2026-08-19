"""Deterministic fixtures for the policy and approval suites.

Ten people is the operating fact `ADR-004` was written against, so the cast here
mirrors it in miniature: an OWNER, a CFO holding OPERATOR + DEPUTY, two plain
OPERATORs and a VIEWER. Every identifier, timestamp and amount is fixed.

The actors are built directly rather than obtained through a login, because
Phase 02 left the HTTP authentication boundary unbuilt and amendment A-3 defers it
again. `ActorContext` is the trusted contract either way, so the approval boundary
under test is the same one production would use; what is not exercised here is the
HTTP hop that produces it. That limitation is recorded, not papered over.
"""

from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from uuid import UUID

from sqlalchemy import Engine, text
from sqlalchemy.orm import Session, sessionmaker

from app.approvals.audit import ApprovalAuditLog
from app.approvals.gate import ProtectedActionGate
from app.approvals.repository import ApprovalRepository
from app.approvals.runtime import ApprovalRuntimeSignal
from app.approvals.service import ApprovalService
from app.contracts import ActorContext
from app.policy.contracts import ActionDescriptor
from app.rate_limit import InMemoryRateLimiter, RateLimitPort
from tests.integration.foundation.support import (
    TENANT_A,
    migration_engine,
    reset_tenant_data,
    runtime_sessions,
    seed_tenant,
)

FIXED_NOW = datetime(2026, 1, 15, 10, 0, tzinfo=UTC)
CORRELATION = UUID("90000000-0000-0000-0000-000000000001")

OWNER_ID = UUID("30000000-0000-0000-0000-000000000001")  # the provisioning owner
CFO_ID = UUID("30000000-0000-0000-0000-0000000000c1")
OPERATOR_1_ID = UUID("30000000-0000-0000-0000-0000000000d1")
OPERATOR_2_ID = UUID("30000000-0000-0000-0000-0000000000d2")
OPERATOR_3_ID = UUID("30000000-0000-0000-0000-0000000000d3")
VIEWER_ID = UUID("30000000-0000-0000-0000-0000000000e1")
SECOND_DEPUTY_ID = UUID("30000000-0000-0000-0000-0000000000c2")

TARGET_ID = UUID("40000000-0000-0000-0000-000000000001")

BUSINESS_PERMISSIONS = (
    "invoice.issue",
    "payment.record",
    "email.send",
    "contact.read",
    "invoice.read",
    "client.write",
)


class MutableClock:
    """A clock a test can advance. Never wall time."""

    def __init__(self, start: datetime = FIXED_NOW) -> None:
        self._now = start

    def __call__(self) -> datetime:
        return self._now

    def advance(self, delta: timedelta) -> None:
        self._now += delta


def reset_and_seed(engine: Engine) -> None:
    reset_tenant_data(engine)
    seed_tenant(engine, TENANT_A, OWNER_ID, "approvals")
    _create_people(engine)


def _create_people(engine: Engine) -> None:
    """Create the cast and their role rows.

    Role membership is written here rather than through `TenantProvisioner`
    because provisioning is Phase-01 code and outside this packet's allowlist.
    The DEPUTY role row itself is created by migration `0003`.
    """
    people = (
        (CFO_ID, "cfo", ("OPERATOR", "DEPUTY")),
        (OPERATOR_1_ID, "operator-1", ("OPERATOR",)),
        (OPERATOR_2_ID, "operator-2", ("OPERATOR",)),
        (OPERATOR_3_ID, "operator-3", ("OPERATOR",)),
        (VIEWER_ID, "viewer", ("VIEWER",)),
    )
    with engine.begin() as connection:
        # FORCE RLS applies to the migration owner too, so even seeding needs the
        # signed transaction context. That is the isolation boundary working as
        # designed, not an obstacle to route around.
        _set_seed_context(connection)

        # Finding F-01: `TenantProvisioner` seeds only OWNER/OPERATOR/VIEWER, so a
        # tenant provisioned *after* migration 0003 has no DEPUTY role row and no
        # approval.decide mapping. The fixture creates them so the database-level
        # rules can be exercised; production still needs the provisioning fix.
        connection.execute(
            text(
                """INSERT INTO roles (id, tenant_id, name, description, created_at, updated_at)
                SELECT gen_random_uuid(), :tenant_id, 'DEPUTY',
                       'Approval deputy: R3 approval authority only', :now, :now
                WHERE NOT EXISTS (
                    SELECT 1 FROM roles WHERE tenant_id = :tenant_id AND name = 'DEPUTY'
                )"""
            ),
            {"tenant_id": TENANT_A, "now": FIXED_NOW},
        )
        for permission_key, role_names in (
            ("approval.decide", ("OWNER", "OPERATOR", "DEPUTY")),
            ("approval.decide.high", ("OWNER", "DEPUTY")),
        ):
            connection.execute(
                text(
                    """INSERT INTO role_permissions (tenant_id, role_id, permission_id,
                                                     granted_by, granted_at)
                    SELECT r.tenant_id, r.id, p.id, :granted_by, :now
                    FROM roles r JOIN permissions p ON p.permission_key = :key
                    WHERE r.tenant_id = :tenant_id AND r.name = ANY(:roles)
                      AND NOT EXISTS (
                          SELECT 1 FROM role_permissions rp
                          WHERE rp.role_id = r.id AND rp.permission_id = p.id
                      )"""
                ),
                {
                    "tenant_id": TENANT_A,
                    "key": permission_key,
                    "roles": list(role_names),
                    "granted_by": OWNER_ID,
                    "now": FIXED_NOW,
                },
            )

        for user_id, label, roles in people:
            connection.execute(
                text(
                    """INSERT INTO users (id, tenant_id, external_subject, display_label,
                                          status, created_at, updated_at)
                    VALUES (:id, :tenant_id, :subject, :label, 'ACTIVE', :now, :now)
                    ON CONFLICT DO NOTHING"""
                ),
                {
                    "id": user_id,
                    "tenant_id": TENANT_A,
                    "subject": f"auth0|{label}",
                    "label": label,
                    "now": FIXED_NOW,
                },
            )
            for role_name in roles:
                connection.execute(
                    text(
                        """INSERT INTO user_roles (tenant_id, user_id, role_id, granted_by,
                                                   granted_at)
                        SELECT :tenant_id, :user_id, r.id, :granted_by, :now
                        FROM roles r WHERE r.tenant_id = :tenant_id AND r.name = :role_name
                        ON CONFLICT DO NOTHING"""
                    ),
                    {
                        "tenant_id": TENANT_A,
                        "user_id": user_id,
                        "granted_by": OWNER_ID,
                        "now": FIXED_NOW,
                        "role_name": role_name,
                    },
                )


def _set_seed_context(connection) -> None:  # type: ignore[no-untyped-def]
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


def _actor(
    actor_id: UUID,
    roles: tuple[str, ...],
    permissions: tuple[str, ...],
    *,
    step_up: bool = False,
    tenant_id: UUID = TENANT_A,
) -> ActorContext:
    return ActorContext(
        tenant_id=tenant_id,
        actor_id=actor_id,
        subject=f"auth0|{actor_id}",
        auth_method="test_fixture",
        assurance="step_up" if step_up else "standard",
        roles=roles,
        permissions=permissions,
        correlation_id=CORRELATION,
    )


def owner(*, step_up: bool = True) -> ActorContext:
    return _actor(
        OWNER_ID,
        ("OWNER",),
        (*BUSINESS_PERMISSIONS, "approval.decide", "approval.decide.high"),
        step_up=step_up,
    )


def cfo(*, step_up: bool = True) -> ActorContext:
    """Holds OPERATOR + DEPUTY, exactly as `ADR-004` §2 describes."""
    return _actor(
        CFO_ID,
        ("OPERATOR", "DEPUTY"),
        (*BUSINESS_PERMISSIONS, "approval.decide", "approval.decide.high"),
        step_up=step_up,
    )


def operator(which: int = 1, *, step_up: bool = True) -> ActorContext:
    identifiers = {1: OPERATOR_1_ID, 2: OPERATOR_2_ID, 3: OPERATOR_3_ID}
    return _actor(
        identifiers[which],
        ("OPERATOR",),
        (*BUSINESS_PERMISSIONS, "approval.decide"),
        step_up=step_up,
    )


def viewer(*, step_up: bool = True) -> ActorContext:
    """A VIEWER holds no decide permission and appears in no slot."""
    return _actor(VIEWER_ID, ("VIEWER",), ("invoice.read",), step_up=step_up)


def unauthorized_operator(*, step_up: bool = True) -> ActorContext:
    """Correct roles, missing the business permission the action requires."""
    return _actor(OPERATOR_1_ID, ("OPERATOR",), ("approval.decide",), step_up=step_up)


def invoice_issue_descriptor(
    *, amount: str = "500.00", target_id: UUID = TARGET_ID, key: str = "fixture-issue-1"
) -> ActionDescriptor:
    return ActionDescriptor(
        action_type="invoice_issue",
        target_type="invoice",
        target_id=target_id,
        normalized_arguments={"amount": amount, "currency": "EUR", "invoice_id": str(target_id)},
        idempotency_key=key,
    )


def email_send_descriptor(*, key: str = "fixture-send-1") -> ActionDescriptor:
    return ActionDescriptor(
        action_type="email_send",
        target_type="email_draft",
        target_id=TARGET_ID,
        normalized_arguments={"draft_id": str(TARGET_ID), "recipient": "anna@example.test"},
        idempotency_key=key,
    )


def client_create_descriptor(*, key: str = "fixture-client-1") -> ActionDescriptor:
    return ActionDescriptor(
        action_type="client_create",
        target_type="client",
        target_id=TARGET_ID,
        normalized_arguments={"name": "Example GmbH"},
        idempotency_key=key,
    )


@dataclass
class Harness:
    """Everything a policy/approval test needs, wired the way production wires it."""

    sessions: sessionmaker[Session]
    clock: MutableClock
    repository: ApprovalRepository
    service: ApprovalService
    gate: ProtectedActionGate
    audit: ApprovalAuditLog
    limiter: RateLimitPort
    signal: ApprovalRuntimeSignal | None = None
    _engine: Engine | None = field(default=None, repr=False)


def build_harness(
    *,
    limiter: RateLimitPort | None = None,
    clock: MutableClock | None = None,
    with_signal: bool = False,
    pool_size: int = 5,
) -> Harness:
    engine = migration_engine()
    reset_and_seed(engine)
    sessions = runtime_sessions(pool_size=pool_size)
    active_clock = clock or MutableClock()
    repository = ApprovalRepository(sessions=sessions)
    audit = ApprovalAuditLog(sessions=sessions)
    service = ApprovalService(repository=repository, audit=audit, clock=active_clock)
    signal = _build_signal(sessions) if with_signal else None
    gate = ProtectedActionGate(
        approvals=service,
        repository=repository,
        limiter=limiter or InMemoryRateLimiter(clock=active_clock),
        audit=audit,
        clock=active_clock,
        signal=signal,
    )
    return Harness(
        sessions=sessions,
        clock=active_clock,
        repository=repository,
        service=service,
        gate=gate,
        audit=audit,
        limiter=gate.limiter,
        signal=signal,
        _engine=engine,
    )


def _build_signal(sessions: sessionmaker[Session]) -> ApprovalRuntimeSignal:
    from app.agent.crypto import AesGcmCheckpointCipher
    from app.agent.events import EventLedger
    from app.agent.operations import OperationRepository
    from app.config import get_settings

    return ApprovalRuntimeSignal(
        operations=OperationRepository(sessions=sessions),
        events=EventLedger(
            sessions=sessions, cipher=AesGcmCheckpointCipher.from_settings(get_settings())
        ),
    )


def audit_actions(
    harness: "Harness", actor: ActorContext, *, target_id: UUID | None = None
) -> list[str]:
    """Audit rows for one tenant.

    Read through a runtime session rather than the guard role: `nexora_rls_guard`
    holds no grant on `audit_events`, and widening a role's access so a test can
    read more easily would be changing the security boundary to suit the test.
    """
    from app.db import set_request_context

    with harness.sessions() as session, session.begin():
        set_request_context(session, actor.tenant_id, actor.actor_id)
        if target_id is None:
            rows = session.execute(
                text("SELECT action FROM audit_events ORDER BY occurred_at, id")
            ).all()
        else:
            rows = session.execute(
                text(
                    """SELECT action FROM audit_events WHERE target_id = :target_id
                    ORDER BY occurred_at, id"""
                ),
                {"target_id": target_id},
            ).all()
    return [row[0] for row in rows]


def total_effects(engine: Engine) -> int:
    """The durable protected-effect count across every tenant.

    Security negatives assert this is zero. Reading it with the guard role rather
    than through the repository means the assertion does not depend on the same
    code path the test is trying to prove wrong.
    """
    with engine.begin() as connection:
        connection.execute(text("SET LOCAL ROLE nexora_rls_guard"))
        try:
            return int(
                connection.execute(
                    text("SELECT COALESCE(sum(effect_count), 0) FROM protected_effect_counters")
                ).scalar_one()
            )
        finally:
            connection.execute(text("RESET ROLE"))


def approval_status(engine: Engine, approval_id: UUID) -> str | None:
    with engine.begin() as connection:
        connection.execute(text("SET LOCAL ROLE nexora_rls_guard"))
        try:
            return connection.execute(
                text("SELECT status FROM approval_requests WHERE id = :id"),
                {"id": approval_id},
            ).scalar_one_or_none()
        finally:
            connection.execute(text("RESET ROLE"))


def decide_all(
    harness: Harness,
    approval_id: UUID,
    payload_hash: str,
    approvers: tuple[ActorContext, ...],
    *,
    key_prefix: str = "decide",
) -> None:
    from app.approvals.contracts import DecisionType

    for index, approver in enumerate(approvers):
        harness.service.decide(
            actor=approver,
            approval_id=approval_id,
            decision=DecisionType.APPROVED,
            payload_hash=payload_hash,
            idempotency_key=f"{key_prefix}-{index}",
        )


Clock = Callable[[], datetime]
