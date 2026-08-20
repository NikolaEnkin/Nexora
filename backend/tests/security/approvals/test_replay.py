"""`P03-006` — concurrent consumption of one grant produces exactly one effect."""

import json
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from uuid import UUID

import pytest
from sqlalchemy import text

from app.approvals.errors import ApprovalReplayed, ApprovalRequired
from app.approvals.gate import GateOutcome
from app.db import set_request_context
from app.policy.canonical import payload_hash
from app.policy.contracts import ActionDescriptor
from tests.integration.approvals.support import (
    build_harness,
    decide_all,
    operator,
    total_effects,
)

pytestmark = pytest.mark.security

FIXTURE = json.loads(Path("backend/tests/fixtures/approvals/concurrent-replay.json").read_text())


def _descriptor() -> ActionDescriptor:
    return ActionDescriptor(
        action_type=FIXTURE["action_type"],
        target_type=FIXTURE["target_type"],
        target_id=UUID(FIXTURE["target_id"]),
        normalized_arguments=FIXTURE["normalized_arguments"],
        idempotency_key=FIXTURE["idempotency_key"],
    )


def test_concurrent_replay_consumes_once() -> None:
    """Ten workers, one grant, one effect.

    The arbiter is `uq_approval_consumptions_single_use`, not a service-side
    read-then-write. Losing workers see the unique violation and convert it into
    a durable no-op that returns the first result reference.
    """
    workers = FIXTURE["workers"]
    harness = build_harness(pool_size=workers + 2)
    engine = harness._engine
    assert engine is not None
    requester = operator(1)
    descriptor = _descriptor()

    with pytest.raises(ApprovalRequired) as pending:
        harness.gate.execute(actor=requester, descriptor=descriptor)
    approval_id = UUID(pending.value.details["approval_id"])
    decide_all(harness, approval_id, payload_hash(descriptor.normalized_arguments), (operator(2),))

    def attempt() -> str:
        try:
            return harness.gate.execute(actor=requester, descriptor=descriptor).outcome.value
        except ApprovalReplayed:
            return "REPLAYED_ERROR"

    with ThreadPoolExecutor(max_workers=workers) as pool:
        outcomes = list(pool.map(lambda _: attempt(), range(workers)))

    executed = outcomes.count(GateOutcome.EXECUTED.value)
    assert executed == FIXTURE["expected"]["executed"], outcomes
    assert len(outcomes) - executed == FIXTURE["expected"]["replayed"]
    assert total_effects(engine) == FIXTURE["expected"]["protected_effect_count"]
    assert _consumption_rows(harness, requester) == FIXTURE["expected"]["consumption_rows"]


def test_a_replayed_decision_creates_one_decision_row() -> None:
    """The same approver submitting twice leaves one decision, not two."""
    harness = build_harness()
    engine = harness._engine
    assert engine is not None
    requester = operator(1)
    descriptor = _descriptor()

    with pytest.raises(ApprovalRequired) as pending:
        harness.gate.execute(actor=requester, descriptor=descriptor)
    approval_id = UUID(pending.value.details["approval_id"])
    digest = payload_hash(descriptor.normalized_arguments)

    for _ in range(3):
        decide_all(harness, approval_id, digest, (operator(2),), key_prefix="repeat")

    decisions = harness.repository.decisions_for(actor=requester, approval_id=approval_id)
    assert len(decisions) == 1
    assert total_effects(engine) == 0


def test_concurrent_decisions_from_one_actor_produce_one_decision() -> None:
    harness = build_harness(pool_size=8)
    requester = operator(1)
    descriptor = _descriptor()

    with pytest.raises(ApprovalRequired) as pending:
        harness.gate.execute(actor=requester, descriptor=descriptor)
    approval_id = UUID(pending.value.details["approval_id"])
    digest = payload_hash(descriptor.normalized_arguments)
    approver = operator(2)

    def attempt(index: int) -> None:
        from app.approvals.contracts import DecisionType

        harness.service.decide(
            actor=approver,
            approval_id=approval_id,
            decision=DecisionType.APPROVED,
            payload_hash=digest,
            idempotency_key=f"race-{index}",
        )

    with ThreadPoolExecutor(max_workers=6) as pool:
        list(pool.map(attempt, range(6)))

    decisions = harness.repository.decisions_for(actor=requester, approval_id=approval_id)
    assert len(decisions) == 1


def _consumption_rows(harness, actor) -> int:  # type: ignore[no-untyped-def]
    with harness.sessions() as session, session.begin():
        set_request_context(session, actor.tenant_id, actor.actor_id)
        return int(session.execute(text("SELECT count(*) FROM approval_consumptions")).scalar_one())
