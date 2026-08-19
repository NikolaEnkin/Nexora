"""`P03-005` — a material edit invalidates the approval (`ARCH-007`, `BR-03-004`)."""

import json
from pathlib import Path
from uuid import UUID

import pytest

from app.approvals.contracts import ApprovalStatus
from app.approvals.errors import ApprovalRequired, ApprovalStale
from app.policy.canonical import payload_hash
from app.policy.contracts import ActionDescriptor
from tests.integration.approvals.support import (
    approval_status,
    build_harness,
    cfo,
    decide_all,
    operator,
    total_effects,
)

pytestmark = pytest.mark.security

FIXTURE = json.loads(Path("backend/tests/fixtures/approvals/approved-then-edited.json").read_text())


def _descriptor(arguments: dict[str, object]) -> ActionDescriptor:
    return ActionDescriptor(
        action_type=FIXTURE["action_type"],
        target_type=FIXTURE["target_type"],
        target_id=UUID(FIXTURE["target_id"]),
        normalized_arguments=arguments,
        idempotency_key=FIXTURE["idempotency_key"],
    )


def test_material_edit_invalidates_grant() -> None:
    """Approve €500, then try to execute €50 000 against the same approval.

    Both the amount and the target change, so this is the strong form of the
    edit: nothing about the approved action survives except the submission
    identity the caller controls.
    """
    harness = build_harness()
    engine = harness._engine
    assert engine is not None
    requester = operator(1)

    original = _descriptor(FIXTURE["original_arguments"])
    with pytest.raises(ApprovalRequired) as pending:
        harness.gate.execute(actor=requester, descriptor=original)
    approval_id = UUID(pending.value.details["approval_id"])

    decide_all(harness, approval_id, payload_hash(original.normalized_arguments), (cfo(),))
    assert approval_status(engine, approval_id) == ApprovalStatus.APPROVED.value

    edited = _descriptor(FIXTURE["edited_arguments"])
    with pytest.raises(ApprovalStale):
        harness.gate.execute(actor=requester, descriptor=edited)

    assert approval_status(engine, approval_id) == FIXTURE["expected"]["approval_status"]
    assert total_effects(engine) == FIXTURE["expected"]["protected_effect_count"]


def test_the_invalidated_grant_cannot_be_reused_for_the_original_payload() -> None:
    """Once stale, the approval is closed — not merely refused for the new payload."""
    harness = build_harness()
    engine = harness._engine
    assert engine is not None
    requester = operator(1)

    original = _descriptor(FIXTURE["original_arguments"])
    with pytest.raises(ApprovalRequired) as pending:
        harness.gate.execute(actor=requester, descriptor=original)
    approval_id = UUID(pending.value.details["approval_id"])
    decide_all(harness, approval_id, payload_hash(original.normalized_arguments), (cfo(),))

    with pytest.raises(ApprovalStale):
        harness.gate.execute(actor=requester, descriptor=_descriptor(FIXTURE["edited_arguments"]))

    # Re-submitting the original payload finds an INVALIDATED approval and stays refused.
    with pytest.raises(ApprovalStale):
        harness.gate.execute(actor=requester, descriptor=original)
    assert total_effects(engine) == 0


def test_a_decision_carrying_a_stale_hash_is_refused_and_closes_the_request() -> None:
    """An approver signing a hash that is not the current one cannot grant."""
    harness = build_harness()
    engine = harness._engine
    assert engine is not None
    requester = operator(1)

    original = _descriptor(FIXTURE["original_arguments"])
    with pytest.raises(ApprovalRequired) as pending:
        harness.gate.execute(actor=requester, descriptor=original)
    approval_id = UUID(pending.value.details["approval_id"])

    wrong_hash = payload_hash(FIXTURE["edited_arguments"])
    with pytest.raises(ApprovalStale):
        decide_all(harness, approval_id, wrong_hash, (cfo(),))

    assert approval_status(engine, approval_id) == ApprovalStatus.INVALIDATED.value
    assert total_effects(engine) == 0


def test_cosmetic_reserialization_does_not_invalidate_an_approval() -> None:
    """The mirror of the rule: a reordered payload still matches.

    Without this, `BR-03-004` would be satisfied trivially by invalidating on any
    byte difference, and every approval would break on a client that serializes
    its JSON in a different key order.

    Only the key order changes. A string-typed `"500.00"` is *not* interchangeable
    with `"500.0"`, and deliberately so: normalization gives numeric canonical form
    to `Decimal` values, never to strings, because `"00500"` as a customer
    reference must not silently become `"500"`.
    """
    harness = build_harness()
    engine = harness._engine
    assert engine is not None
    requester = operator(1)

    ordered = _descriptor(
        {
            "amount": "500.00",
            "currency": "EUR",
            "invoice_id": "40000000-0000-0000-0000-000000000001",
        }
    )
    with pytest.raises(ApprovalRequired) as pending:
        harness.gate.execute(actor=requester, descriptor=ordered)
    approval_id = UUID(pending.value.details["approval_id"])
    decide_all(harness, approval_id, payload_hash(ordered.normalized_arguments), (cfo(),))

    reordered = _descriptor(
        {
            "invoice_id": "40000000-0000-0000-0000-000000000001",
            "currency": "EUR",
            "amount": "500.00",
        }
    )
    result = harness.gate.execute(actor=requester, descriptor=reordered)
    assert result.result_ref is not None
    assert total_effects(engine) == 1
