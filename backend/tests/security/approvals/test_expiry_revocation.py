"""`P03-007` — expired, revoked and wrong-approver approvals execute nothing.

The clock is a fixture the test advances. Expiry is never observed by sleeping,
and never by trusting a caller-supplied timestamp: the service reads its own
clock, so a client cannot extend an approval by claiming an earlier time.
"""

from datetime import timedelta
from pathlib import Path
from typing import Any
from uuid import UUID

import pytest
import yaml

from app.approvals.contracts import ApprovalStatus, DecisionType
from app.approvals.errors import (
    ApprovalExpired,
    ApprovalNotAuthorized,
    ApprovalNotFound,
    ApprovalRequired,
    ApprovalRevoked,
)
from app.policy.canonical import payload_hash
from tests.integration.approvals.support import (
    MutableClock,
    approval_status,
    build_harness,
    cfo,
    client_create_descriptor,
    decide_all,
    invoice_issue_descriptor,
    operator,
    total_effects,
    viewer,
)

pytestmark = pytest.mark.security

FIXTURE: dict[str, Any] = yaml.safe_load(
    Path("backend/tests/fixtures/approvals/expired-revoked-wrong-actor.yaml").read_text()
)
CASES = {case["name"]: case for case in FIXTURE["cases"]}


def test_an_expired_approval_executes_nothing() -> None:
    case = CASES["expired"]
    clock = MutableClock()
    harness = build_harness(clock=clock)
    engine = harness._engine
    assert engine is not None
    requester = operator(1)
    descriptor = client_create_descriptor(key=case["idempotency_key"])

    with pytest.raises(ApprovalRequired) as pending:
        harness.gate.execute(actor=requester, descriptor=descriptor)
    approval_id = UUID(pending.value.details["approval_id"])
    decide_all(harness, approval_id, payload_hash(descriptor.normalized_arguments), (operator(2),))
    assert approval_status(engine, approval_id) == ApprovalStatus.APPROVED.value

    clock.advance(timedelta(minutes=case["advance_minutes"]))

    with pytest.raises(ApprovalExpired):
        harness.gate.execute(actor=requester, descriptor=descriptor)
    assert approval_status(engine, approval_id) == case["expected_status"]
    assert total_effects(engine) == case["protected_effect_count"]


def test_a_revoked_approval_executes_nothing() -> None:
    case = CASES["revoked"]
    harness = build_harness()
    engine = harness._engine
    assert engine is not None
    requester = operator(1)
    descriptor = client_create_descriptor(key=case["idempotency_key"])

    with pytest.raises(ApprovalRequired) as pending:
        harness.gate.execute(actor=requester, descriptor=descriptor)
    approval_id = UUID(pending.value.details["approval_id"])
    decide_all(harness, approval_id, payload_hash(descriptor.normalized_arguments), (operator(2),))

    harness.service.revoke(actor=cfo(), approval_id=approval_id)

    with pytest.raises(ApprovalRevoked):
        harness.gate.execute(actor=requester, descriptor=descriptor)
    assert approval_status(engine, approval_id) == case["expected_status"]
    assert total_effects(engine) == case["protected_effect_count"]


def test_a_wrong_approver_cannot_grant() -> None:
    case = CASES["wrong_approver"]
    harness = build_harness()
    engine = harness._engine
    assert engine is not None
    requester = operator(1)
    descriptor = client_create_descriptor(key=case["idempotency_key"])

    with pytest.raises(ApprovalRequired) as pending:
        harness.gate.execute(actor=requester, descriptor=descriptor)
    approval_id = UUID(pending.value.details["approval_id"])

    with pytest.raises(ApprovalNotAuthorized):
        harness.service.decide(
            actor=viewer(),
            approval_id=approval_id,
            decision=DecisionType.APPROVED,
            payload_hash=payload_hash(descriptor.normalized_arguments),
            idempotency_key="viewer-decide",
        )

    assert approval_status(engine, approval_id) == case["expected_status"]
    assert total_effects(engine) == case["protected_effect_count"]


def test_expiry_with_a_partial_composition_executes_nothing() -> None:
    """`ADR-004` §Verification — a half-approved path 5 that runs out of time."""
    case = CASES["partial_composition_at_expiry"]
    clock = MutableClock()
    harness = build_harness(clock=clock)
    engine = harness._engine
    assert engine is not None
    requester = operator(1)
    descriptor = invoice_issue_descriptor(amount=case["amount"], key=case["idempotency_key"])

    with pytest.raises(ApprovalRequired) as pending:
        harness.gate.execute(actor=requester, descriptor=descriptor)
    approval_id = UUID(pending.value.details["approval_id"])

    # One of the three slots path 5 requires.
    decide_all(harness, approval_id, payload_hash(descriptor.normalized_arguments), (operator(2),))
    assert approval_status(engine, approval_id) == ApprovalStatus.PENDING.value

    clock.advance(timedelta(minutes=case["advance_minutes"]))

    with pytest.raises(ApprovalExpired):
        harness.gate.execute(actor=requester, descriptor=descriptor)
    assert approval_status(engine, approval_id) == case["expected_status"]
    assert total_effects(engine) == case["protected_effect_count"]


def test_a_decision_after_expiry_cannot_complete_a_composition() -> None:
    """The remaining approver arriving late closes the request instead of granting."""
    clock = MutableClock()
    harness = build_harness(clock=clock)
    engine = harness._engine
    assert engine is not None
    requester = operator(1)
    descriptor = invoice_issue_descriptor(amount="50000.00", key="late-decision")
    digest = payload_hash(descriptor.normalized_arguments)

    with pytest.raises(ApprovalRequired) as pending:
        harness.gate.execute(actor=requester, descriptor=descriptor)
    approval_id = UUID(pending.value.details["approval_id"])
    decide_all(harness, approval_id, digest, (operator(2),))

    clock.advance(timedelta(minutes=121))

    with pytest.raises(ApprovalExpired):
        decide_all(harness, approval_id, digest, (operator(3), cfo()), key_prefix="late")

    assert approval_status(engine, approval_id) == ApprovalStatus.EXPIRED.value
    assert total_effects(engine) == 0


def test_a_guessed_approval_identifier_is_non_disclosing() -> None:
    """An identifier that does not belong to this tenant reads as absent."""
    harness = build_harness()
    engine = harness._engine
    assert engine is not None

    with pytest.raises(ApprovalNotFound):
        harness.service.decide(
            actor=operator(1),
            approval_id=UUID("00000000-0000-0000-0000-0000000000ff"),
            decision=DecisionType.APPROVED,
            payload_hash="0" * 64,
            idempotency_key="guess-1",
        )
    assert total_effects(engine) == 0
