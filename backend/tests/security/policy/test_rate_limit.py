"""`P03-008` — the rate limit stops work at the configured boundary, and no secret leaks."""

import json
import logging
from pathlib import Path
from uuid import UUID

import pytest
from sqlalchemy import text

from app.db import set_request_context
from app.policy.contracts import ActionDescriptor
from app.policy.errors import RateLimited
from app.rate_limit import UnavailableRateLimiter
from tests.integration.approvals.support import (
    build_harness,
    client_create_descriptor,
    operator,
    total_effects,
)

pytestmark = pytest.mark.security

FIXTURE = json.loads(Path("backend/tests/fixtures/policy/rate-burst-secret.json").read_text())
SECRET = FIXTURE["fake_secret"]


def _read_descriptor(index: int) -> ActionDescriptor:
    """A burst of reads carrying a fake secret in the payload."""
    return ActionDescriptor(
        action_type=FIXTURE["action_type"],
        target_type=FIXTURE["target_type"],
        target_id=UUID(FIXTURE["target_id"]),
        normalized_arguments={"invoice_id": FIXTURE["target_id"], "note": SECRET},
        idempotency_key=f"burst-{index}",
    )


def test_fixed_burst_blocks_before_model_and_redacts(
    monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    """The limit is enforced before policy runs, so refused calls cost nothing.

    `evaluate` is counted rather than mocked away: it is the first thing that would
    read the payload and, in later phases, the gateway to a model call. If the
    limiter let a call through, the counter would show it.
    """
    harness = build_harness()
    engine = harness._engine
    assert engine is not None
    actor = operator(1)

    import app.approvals.gate as gate_module

    evaluations = 0
    real_evaluate = gate_module.evaluate

    def counting_evaluate(**kwargs):  # type: ignore[no-untyped-def]
        nonlocal evaluations
        evaluations += 1
        return real_evaluate(**kwargs)

    monkeypatch.setattr(gate_module, "evaluate", counting_evaluate)

    allowed = 0
    limited = 0
    retry_after: set[int] = set()
    with caplog.at_level(logging.DEBUG):
        for index in range(FIXTURE["burst"]):
            try:
                harness.gate.execute(actor=actor, descriptor=_read_descriptor(index))
                allowed += 1
            except RateLimited as error:
                limited += 1
                retry_after.add(int(error.details["retry_after"]))

    assert allowed == FIXTURE["expected"]["allowed"]
    assert limited == FIXTURE["expected"]["rate_limited"]
    assert retry_after == {FIXTURE["expected"]["retry_after_seconds"]}
    # Nothing past the boundary reached policy evaluation.
    assert evaluations == FIXTURE["expected"]["allowed"]
    # R1 reads create no approval and no protected effect.
    assert total_effects(engine) == 0

    leaked = [record for record in caplog.records if SECRET in record.getMessage()]
    assert leaked == [], "the fake secret reached a log record"
    assert (
        _secret_occurrences_in_audit(harness, actor)
        == (FIXTURE["expected"]["secret_occurrences_in_logs"])
    )


def test_a_protected_action_fails_closed_when_the_rate_store_is_unavailable() -> None:
    """Packet §12 — store ambiguity refuses a protected action rather than allowing it."""
    harness = build_harness(limiter=UnavailableRateLimiter())
    engine = harness._engine
    assert engine is not None

    with pytest.raises(RateLimited):
        harness.gate.execute(actor=operator(1), descriptor=client_create_descriptor())

    assert total_effects(engine) == 0
    assert _approval_request_count(harness, operator(1)) == 0


def test_a_read_degrades_open_when_the_rate_store_is_unavailable() -> None:
    """A cache outage must not convert every read into an outage."""
    harness = build_harness(limiter=UnavailableRateLimiter())
    engine = harness._engine
    assert engine is not None

    result = harness.gate.execute(actor=operator(1), descriptor=_read_descriptor(0))
    assert result.approval is None
    assert total_effects(engine) == 0


def test_the_limit_is_per_actor_not_global() -> None:
    """One actor exhausting their budget does not refuse another's work."""
    harness = build_harness()
    first = operator(1)
    second = operator(2)

    for index in range(FIXTURE["limit_per_minute"]):
        harness.gate.execute(actor=first, descriptor=_read_descriptor(index))
    with pytest.raises(RateLimited):
        harness.gate.execute(actor=first, descriptor=_read_descriptor(999))

    # The second actor is unaffected.
    harness.gate.execute(actor=second, descriptor=_read_descriptor(0))


def _secret_occurrences_in_audit(harness, actor) -> int:  # type: ignore[no-untyped-def]
    with harness.sessions() as session, session.begin():
        set_request_context(session, actor.tenant_id, actor.actor_id)
        rows = session.execute(text("SELECT metadata::text FROM audit_events")).all()
    return sum(1 for row in rows if SECRET in row[0])


def _approval_request_count(harness, actor) -> int:  # type: ignore[no-untyped-def]
    with harness.sessions() as session, session.begin():
        set_request_context(session, actor.tenant_id, actor.actor_id)
        return int(session.execute(text("SELECT count(*) FROM approval_requests")).scalar_one())
