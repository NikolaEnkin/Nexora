"""`P03-002` — approval cannot grant a permission the actor does not hold."""

import json
from pathlib import Path

import pytest

from app.errors import AuthorizationDenied
from app.policy.contracts import ActionDescriptor
from tests.integration.approvals.support import (
    build_harness,
    total_effects,
    unauthorized_operator,
)

pytestmark = pytest.mark.security

FIXTURE = json.loads(
    Path("backend/tests/fixtures/approvals/valid-grant-unauthorized-actor.json").read_text()
)


def _descriptor() -> ActionDescriptor:
    from uuid import UUID

    return ActionDescriptor(
        action_type=FIXTURE["action_type"],
        target_type=FIXTURE["target_type"],
        target_id=UUID(FIXTURE["target_id"]),
        normalized_arguments=FIXTURE["normalized_arguments"],
        idempotency_key=FIXTURE["idempotency_key"],
    )


def test_approval_cannot_grant_missing_permission() -> None:
    """An actor holding `approval.decide` but not `invoice.issue` is denied.

    The important part is not merely the error: it is that **no approval request
    exists afterwards**. Authorization runs before policy, so the unauthorized
    actor never reaches the stage that would create a request they could later
    have someone sign.
    """
    harness = build_harness()
    engine = harness._engine
    assert engine is not None
    actor = unauthorized_operator()

    with pytest.raises(AuthorizationDenied):
        harness.gate.execute(actor=actor, descriptor=_descriptor())

    assert total_effects(engine) == FIXTURE["expected"]["protected_effect_count"]
    assert _approval_request_count(harness) == FIXTURE["expected"]["approval_requests_created"]


def test_a_denied_actor_cannot_reach_the_approval_stage_by_retrying() -> None:
    harness = build_harness()
    engine = harness._engine
    assert engine is not None
    actor = unauthorized_operator()

    for _ in range(3):
        with pytest.raises(AuthorizationDenied):
            harness.gate.execute(actor=actor, descriptor=_descriptor())

    assert total_effects(engine) == 0
    assert _approval_request_count(harness) == 0


def test_a_foreign_tenant_object_is_denied_without_disclosure() -> None:
    """A guessed identifier from another tenant is refused, and says nothing."""
    from uuid import UUID

    harness = build_harness()
    engine = harness._engine
    assert engine is not None
    from tests.integration.approvals.support import operator

    foreign_tenant = UUID("20000000-0000-0000-0000-0000000000ff")
    with pytest.raises(AuthorizationDenied):
        harness.gate.execute(
            actor=operator(1),
            descriptor=_descriptor(),
            object_tenant_id=foreign_tenant,
        )
    assert total_effects(engine) == 0
    assert _approval_request_count(harness) == 0


def _approval_request_count(harness) -> int:  # type: ignore[no-untyped-def]
    from sqlalchemy import text

    from app.db import set_request_context
    from tests.integration.approvals.support import operator

    actor = operator(1)
    with harness.sessions() as session, session.begin():
        set_request_context(session, actor.tenant_id, actor.actor_id)
        return int(session.execute(text("SELECT count(*) FROM approval_requests")).scalar_one())
