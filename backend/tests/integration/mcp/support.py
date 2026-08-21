"""Wiring for the MCP tests.

The gateway is built over the *real* Phase-03 policy gate, not a stand-in. That
matters: `client_create` and `client_update` are R2 under `ADR-004`, so every write
in these tests goes through an actual approval. A test double for the policy gate
would make the tools look simpler than they are and would hide exactly the
integration this phase exists to build.
"""

from dataclasses import dataclass
from datetime import datetime
from uuid import UUID, uuid4

from sqlalchemy import Engine, text
from sqlalchemy.orm import Session, sessionmaker

from app.approvals.contracts import DecisionType
from app.business.clients.service import ClientService
from app.contracts import ActorContext
from app.db import set_request_context
from app.mcp.contracts import ToolAudience, ToolCallEnvelope, ToolOutcome
from app.mcp.gateway import McpGateway
from app.policy.canonical import payload_hash
from tests.integration.approvals.support import (
    CFO_ID,
    OPERATOR_1_ID,
    OPERATOR_2_ID,
    OWNER_ID,
    VIEWER_ID,
    Harness,
    MutableClock,
    build_harness,
)
from tests.integration.foundation.support import TENANT_A

# The Phase-03 fixture grants no `client.read`, because Phase 03 had no clients.
# These factories live here rather than being added there: a Phase-04 need should
# not edit a Phase-03 test file.
CORRELATION = UUID("90000000-0000-0000-0000-000000000001")
CLIENT_PERMISSIONS = ("client.read", "client.write")


def _actor(actor_id: UUID, roles: tuple[str, ...], permissions: tuple[str, ...]) -> ActorContext:
    return ActorContext(
        tenant_id=TENANT_A,
        actor_id=actor_id,
        subject=f"auth0|{actor_id}",
        auth_method="test_fixture",
        assurance="step_up",
        roles=roles,
        permissions=permissions,
        correlation_id=CORRELATION,
    )


def operator(which: int = 1) -> ActorContext:
    identifiers = {1: OPERATOR_1_ID, 2: OPERATOR_2_ID}
    return _actor(identifiers[which], ("OPERATOR",), (*CLIENT_PERMISSIONS, "approval.decide"))


def owner() -> ActorContext:
    return _actor(
        OWNER_ID,
        ("OWNER",),
        (*CLIENT_PERMISSIONS, "approval.decide", "approval.decide.high"),
    )


def cfo() -> ActorContext:
    return _actor(
        CFO_ID,
        ("OPERATOR", "DEPUTY"),
        (*CLIENT_PERMISSIONS, "approval.decide", "approval.decide.high"),
    )


def viewer() -> ActorContext:
    """Holds `client.read` but not `client.write`: authorized to look, not to change."""
    return _actor(VIEWER_ID, ("VIEWER",), ("client.read",))


@dataclass
class McpHarness:
    approvals: Harness
    gateway: McpGateway
    clients: ClientService
    clock: MutableClock
    engine: Engine
    sessions: sessionmaker[Session]


def build_mcp_harness(*, pool_size: int = 5) -> McpHarness:
    approvals = build_harness(pool_size=pool_size)
    engine = approvals._engine
    assert engine is not None
    clients = ClientService(sessions=approvals.sessions)
    gateway = McpGateway(
        clients=clients,
        policy_gate=approvals.gate,
        clock=approvals.clock,
    )
    return McpHarness(
        approvals=approvals,
        gateway=gateway,
        clients=clients,
        clock=approvals.clock,
        engine=engine,
        sessions=approvals.sessions,
    )


def envelope(
    tool_name: str,
    arguments: dict[str, object],
    *,
    audience: ToolAudience = ToolAudience.AGENT,
    idempotency_key: str | None = None,
    request_id: UUID | None = None,
) -> ToolCallEnvelope:
    return ToolCallEnvelope(
        request_id=request_id or uuid4(),
        tool_name=tool_name,
        tool_version=1,
        audience=audience,
        typed_arguments=arguments,
        idempotency_key=idempotency_key,
    )


def approve_pending(
    harness: McpHarness,
    actor: ActorContext,
    call: ToolCallEnvelope,
    *,
    approver: ActorContext | None = None,
) -> UUID:
    """Run a write once to open its approval, then have somebody decide it.

    Returns the approval id. The first call always comes back
    `APPROVAL_REQUIRED`: that is the R2 contract, not a test inconvenience. The
    gateway reports it as an outcome rather than raising, so a caller can act on
    it.
    """
    opened = harness.gateway.call(actor=actor, envelope=call, authenticated_audience=call.audience)
    if opened.outcome is not ToolOutcome.APPROVAL_REQUIRED:  # pragma: no cover
        raise AssertionError(f"expected APPROVAL_REQUIRED, got {opened.outcome}")
    assert opened.error is not None
    approval_id = UUID(opened.error.details["approval_id"])

    digest = _stored_hash(harness, actor, approval_id)
    harness.approvals.service.decide(
        actor=approver or owner(),
        approval_id=approval_id,
        decision=DecisionType.APPROVED,
        payload_hash=digest,
        idempotency_key=f"decide-{approval_id}",
    )
    return approval_id


def _stored_hash(harness: McpHarness, actor: ActorContext, approval_id: UUID) -> str:
    request = harness.approvals.repository.load(actor=actor, approval_id=approval_id)
    assert request is not None
    return request.payload_hash


def counts(harness: McpHarness, actor: ActorContext) -> dict[str, int]:
    """Durable row counts for the tables a client write must touch exactly once."""
    with harness.sessions() as session, session.begin():
        set_request_context(session, actor.tenant_id, actor.actor_id)
        return {
            "clients": int(session.execute(text("SELECT count(*) FROM clients")).scalar_one()),
            "domain_events": int(
                session.execute(
                    text("SELECT count(*) FROM domain_events WHERE aggregate_type = 'client'")
                ).scalar_one()
            ),
            "outbox_events": int(
                session.execute(
                    text(
                        """SELECT count(*) FROM outbox_events o
                        JOIN domain_events d ON d.id = o.domain_event_id
                        WHERE d.aggregate_type = 'client'"""
                    )
                ).scalar_one()
            ),
            "audit_events": int(
                session.execute(
                    text("SELECT count(*) FROM audit_events WHERE target_type = 'client'")
                ).scalar_one()
            ),
        }


__all__ = [
    "McpHarness",
    "approve_pending",
    "build_mcp_harness",
    "cfo",
    "counts",
    "datetime",
    "envelope",
    "operator",
    "owner",
    "payload_hash",
    "viewer",
]
