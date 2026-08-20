"""The approvals API contract — packet §8.

These are contract tests, so they assert the exact shapes and the exact refusals.
They run against the real router with a trusted actor injected on
`request.state`, which is the same seam `POST /chat` uses while amendment A-3
leaves the HTTP authentication boundary to Phase 04.
"""

from uuid import UUID

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from app.api.approvals import ApprovalApiDependencies, router
from app.approvals.contracts import ApprovalStatus
from app.approvals.errors import ApprovalRequired
from app.errors import install_error_handlers
from app.policy.canonical import payload_hash
from tests.integration.approvals.support import (
    build_harness,
    client_create_descriptor,
    operator,
    total_effects,
    viewer,
)

pytestmark = pytest.mark.contract


def _client(harness, actor):  # type: ignore[no-untyped-def]
    app = FastAPI()
    install_error_handlers(app)
    app.include_router(router)
    app.state.approvals = ApprovalApiDependencies(service=harness.service)

    @app.middleware("http")
    async def attach_actor(request, call_next):  # type: ignore[no-untyped-def]
        request.state.actor = actor
        return await call_next(request)

    return TestClient(app, raise_server_exceptions=False)


def _pending_approval(harness):  # type: ignore[no-untyped-def]
    descriptor = client_create_descriptor(key="api-1")
    with pytest.raises(ApprovalRequired) as pending:
        harness.gate.execute(actor=operator(1), descriptor=descriptor)
    return UUID(pending.value.details["approval_id"]), payload_hash(descriptor.normalized_arguments)


def test_reading_an_approval_returns_the_safe_projection() -> None:
    harness = build_harness()
    approval_id, digest = _pending_approval(harness)

    response = _client(harness, operator(2)).get(f"/approvals/{approval_id}")

    assert response.status_code == 200
    body = response.json()
    assert body["version"] == "1"
    assert body["approval_id"] == str(approval_id)
    assert body["payload_hash"] == digest
    assert body["status"] == ApprovalStatus.PENDING.value
    # The stored payload is never re-emitted through this endpoint.
    assert "payload" not in body


def test_approving_with_the_current_hash_grants() -> None:
    harness = build_harness()
    approval_id, digest = _pending_approval(harness)

    response = _client(harness, operator(2)).post(
        f"/approvals/{approval_id}/approve",
        json={
            "version": "1",
            "approval_version": "1",
            "payload_hash": digest,
            "idempotency_key": "api-approve-1",
        },
    )

    assert response.status_code == 200
    assert response.json()["status"] == ApprovalStatus.APPROVED.value


def test_approving_with_a_stale_hash_is_refused() -> None:
    harness = build_harness()
    engine = harness._engine
    assert engine is not None
    approval_id, _ = _pending_approval(harness)

    response = _client(harness, operator(2)).post(
        f"/approvals/{approval_id}/approve",
        json={
            "version": "1",
            "approval_version": "1",
            "payload_hash": "a" * 64,
            "idempotency_key": "api-stale-1",
        },
    )

    assert response.status_code == 409
    assert response.json()["code"] == "APPROVAL_STALE"
    assert total_effects(engine) == 0


def test_a_body_carrying_an_identity_or_a_verdict_is_rejected() -> None:
    """`extra="forbid"`: there is no field for a caller to escalate through."""
    harness = build_harness()
    approval_id, digest = _pending_approval(harness)
    client = _client(harness, operator(2))

    for smuggled in (
        {"actor_id": "30000000-0000-0000-0000-0000000000a1"},
        {"roles": ["OWNER"]},
        {"permissions": ["approval.decide.high"]},
        {"assurance": "step_up"},
        {"approved": True},
        {"decision": "APPROVED"},
    ):
        response = client.post(
            f"/approvals/{approval_id}/approve",
            json={
                "version": "1",
                "approval_version": "1",
                "payload_hash": digest,
                "idempotency_key": "api-smuggle",
                **smuggled,
            },
        )
        assert response.status_code == 422, smuggled


def test_an_unauthorized_approver_is_refused() -> None:
    harness = build_harness()
    engine = harness._engine
    assert engine is not None
    approval_id, digest = _pending_approval(harness)

    response = _client(harness, viewer()).post(
        f"/approvals/{approval_id}/approve",
        json={
            "version": "1",
            "approval_version": "1",
            "payload_hash": digest,
            "idempotency_key": "api-viewer-1",
        },
    )

    assert response.status_code == 403
    assert response.json()["code"] == "APPROVAL_NOT_AUTHORIZED"
    assert total_effects(engine) == 0


def test_a_guessed_identifier_is_non_disclosing() -> None:
    harness = build_harness()
    absent = UUID("00000000-0000-0000-0000-0000000000ff")

    response = _client(harness, operator(1)).get(f"/approvals/{absent}")

    assert response.status_code == 404
    assert response.json()["code"] == "APPROVAL_NOT_FOUND"
    # The envelope carries no detail that would distinguish absent from foreign.
    assert response.json()["details"] == {}


def test_rejecting_terminates_the_request() -> None:
    harness = build_harness()
    engine = harness._engine
    assert engine is not None
    approval_id, digest = _pending_approval(harness)

    response = _client(harness, operator(2)).post(
        f"/approvals/{approval_id}/reject",
        json={
            "version": "1",
            "approval_version": "1",
            "payload_hash": digest,
            "idempotency_key": "api-reject-1",
        },
    )

    assert response.status_code == 200
    assert response.json()["status"] == ApprovalStatus.REJECTED.value
    assert total_effects(engine) == 0


def test_cancelling_terminates_the_request() -> None:
    harness = build_harness()
    approval_id, _ = _pending_approval(harness)

    response = _client(harness, operator(1)).post(f"/approvals/{approval_id}/cancel")

    assert response.status_code == 200
    assert response.json()["status"] == ApprovalStatus.CANCELLED.value


def test_a_request_without_a_trusted_actor_is_refused() -> None:
    """No actor on `request.state` means no decision, rather than a default identity."""
    harness = build_harness()
    approval_id, digest = _pending_approval(harness)

    app = FastAPI()
    install_error_handlers(app)
    app.include_router(router)
    app.state.approvals = ApprovalApiDependencies(service=harness.service)
    client = TestClient(app, raise_server_exceptions=False)

    response = client.post(
        f"/approvals/{approval_id}/approve",
        json={
            "version": "1",
            "approval_version": "1",
            "payload_hash": digest,
            "idempotency_key": "api-noauth",
        },
    )
    assert response.status_code == 401
