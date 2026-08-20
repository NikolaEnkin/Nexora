"""`P03-001` and catalogue integrity against accepted `ADR-004` §1.

The completeness test exists because the catalogue is the security boundary's
data half. A silently dropped or reclassified action would not fail any behaviour
test that does not name it, so the whole table is asserted, not sampled.
"""

from pathlib import Path
from typing import Any
from uuid import UUID

import pytest
import yaml

from app.contracts import ActorContext
from app.policy import CATALOGUE, ActionDescriptor, RiskLevel, evaluate, lookup
from app.policy.catalogue import AMOUNT_THRESHOLD, RATE_LIMIT_PER_MINUTE
from app.policy.contracts import Assurance

FIXTURE = Path("backend/tests/fixtures/policy/r1-read.yaml")

# Transcribed from ADR-004 §1. Any divergence between this table and the shipped
# catalogue is a defect in one of them; the test does not say which.
EXPECTED_R1 = {
    "client_get": "client.read",
    "offer_get": "offer.read",
    "offer_items": "offer.read",
    "invoice_get": "invoice.read",
    "invoice_items": "invoice.read",
    "invoice_list_unpaid": "invoice.read",
    "offer_validate": "offer.write",
    "invoice_validate": "invoice.write",
    "email_account_list": "email.read",
    "email_draft_get": "email.read",
    "email_thread_recent": "email.read",
}
EXPECTED_R2 = {
    "client_create": "client.write",
    "client_update": "client.write",
    "offer_draft_create": "offer.write",
    "invoice_draft_create": "invoice.write",
    "email_draft_create": "email.draft",
    "email_draft_update": "email.draft",
    "contact_resolve": "contact.read",
    "email_send": "email.send",
}
EXPECTED_R3 = {
    "invoice_issue": "invoice.issue",
    "payment_record": "payment.record",
}


@pytest.mark.unit
def test_r1_fixture_is_allowed_exactly() -> None:
    """`P03-001` — an authorized R1 action evaluates to an exact `ALLOW`."""
    loaded: dict[str, Any] = yaml.safe_load(FIXTURE.read_text())
    actor = ActorContext(
        tenant_id=UUID(loaded["actor"]["tenant_id"]),
        actor_id=UUID(loaded["actor"]["actor_id"]),
        subject=loaded["actor"]["subject"],
        auth_method=loaded["actor"]["auth_method"],
        assurance=loaded["actor"]["assurance"],
        roles=tuple(loaded["actor"]["roles"]),
        permissions=tuple(loaded["actor"]["permissions"]),
        correlation_id=UUID(loaded["actor"]["correlation_id"]),
    )
    descriptor = ActionDescriptor(
        action_type=loaded["descriptor"]["action_type"],
        target_type=loaded["descriptor"]["target_type"],
        target_id=UUID(loaded["descriptor"]["target_id"]),
        normalized_arguments=loaded["descriptor"]["normalized_arguments"],
        idempotency_key=loaded["descriptor"]["idempotency_key"],
    )

    decision = evaluate(actor=actor, descriptor=descriptor, object_tenant_id=actor.tenant_id)

    expected = loaded["expected"]
    assert decision.effect.value == expected["effect"]
    assert decision.risk.value == expected["risk"]
    assert decision.reason_code.value == expected["reason_code"]
    assert decision.required_permission == expected["required_permission"]
    assert decision.required_assurance.value == expected["required_assurance"]
    assert decision.policy_version == expected["policy_version"]
    assert decision.catalogue_version == expected["catalogue_version"]
    assert decision.normalization_version == expected["normalization_version"]
    assert list(decision.approval_path_ids) == expected["approval_path_ids"]
    # No approval is created for R1, and nothing mutable was touched.
    assert decision.payload_hash == decision.payload_hash.lower()
    assert len(decision.payload_hash) == 64


@pytest.mark.unit
def test_catalogue_matches_the_accepted_adr_exactly() -> None:
    by_risk = {
        RiskLevel.R1: EXPECTED_R1,
        RiskLevel.R2: EXPECTED_R2,
        RiskLevel.R3: EXPECTED_R3,
    }
    expected_keys = set(EXPECTED_R1) | set(EXPECTED_R2) | set(EXPECTED_R3)
    assert set(CATALOGUE) == expected_keys

    for risk, expected in by_risk.items():
        for action_key, permission in expected.items():
            entry = CATALOGUE[action_key]
            assert entry.risk is risk, action_key
            assert entry.required_permission == permission, action_key


@pytest.mark.unit
def test_email_send_and_contact_resolve_are_r2_regardless_of_recipient() -> None:
    """`ADR-004` §1: no autonomous send path, and the recipient passes a human twice."""
    assert CATALOGUE["email_send"].risk is RiskLevel.R2
    assert CATALOGUE["contact_resolve"].risk is RiskLevel.R2


@pytest.mark.unit
def test_r3_actions_are_r3_at_every_amount_and_require_step_up() -> None:
    """`ADR-004` §1: the amount changes the composition, never the risk level."""
    for action_key in EXPECTED_R3:
        entry = CATALOGUE[action_key]
        assert entry.risk is RiskLevel.R3
        assert entry.required_assurance is Assurance.STEP_UP
        assert entry.amount_field is not None


@pytest.mark.unit
def test_unknown_action_is_not_classified() -> None:
    assert lookup("invoice_delete_everything") is None


@pytest.mark.unit
def test_rate_limits_match_the_accepted_adr() -> None:
    assert RATE_LIMIT_PER_MINUTE[RiskLevel.R1] == 120
    assert RATE_LIMIT_PER_MINUTE[RiskLevel.R2] == 30
    assert RATE_LIMIT_PER_MINUTE[RiskLevel.R3] == 10


@pytest.mark.unit
def test_amount_threshold_matches_the_accepted_adr() -> None:
    assert str(AMOUNT_THRESHOLD) == "10000"
