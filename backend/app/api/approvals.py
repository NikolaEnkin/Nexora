"""`GET /approvals/{id}` and the approve / reject / cancel decision endpoints.

The actor comes only from the trusted boundary. `ApprovalDecisionRequest` forbids
extra fields, so a body carrying `actor_id`, `roles`, `permissions`, `assurance`
or `approved: true` is a validation error rather than an escalation — there is no
field for a caller to put an identity or a verdict in.

`payload_hash` is **required** in the body and is compared against the stored
request. That is what makes an approver's decision a decision about a specific
payload rather than about an identifier: a client that renders one payload and
signs another is refused with `APPROVAL_STALE`.

No HTTP authentication boundary exists yet (Phase-02 known limitation, deferred
again by amendment A-3). These handlers therefore read `request.state.actor`
exactly as `POST /chat` does, and the security properties proved for Phase 03 are
proved at the service boundary. Wiring the session boundary to HTTP is Phase 04.
"""

from dataclasses import dataclass
from typing import Literal
from uuid import UUID

from fastapi import APIRouter, Request, Response, status
from fastapi.responses import JSONResponse
from pydantic import Field, ValidationError

from app.approvals.contracts import ApprovalRequest, DecisionType
from app.approvals.errors import ApprovalNotFound
from app.approvals.service import ApprovalService
from app.contracts import ActorContext
from app.contracts.foundation import FrozenContract
from app.errors import ApplicationError, AuthenticationRequired

router = APIRouter(prefix="/approvals", tags=["approvals"])

MAX_IDEMPOTENCY_KEY_LENGTH = 255


class ApprovalDecisionRequest(FrozenContract):
    """`extra="forbid"` is the security control, exactly as in `ChatRequest`."""

    version: Literal["1"] = "1"
    approval_version: Literal["1"] = "1"
    payload_hash: str = Field(pattern="^[a-f0-9]{64}$")
    idempotency_key: str = Field(min_length=1, max_length=MAX_IDEMPOTENCY_KEY_LENGTH)


class ApprovalView(FrozenContract):
    """The safe projection of an approval.

    The stored payload is deliberately absent. An approver's client renders the
    payload it is asking about; this endpoint confirms *which* payload the server
    holds, by hash, without re-emitting business content through a second channel.
    """

    version: Literal["1"] = "1"
    approval_id: UUID
    action_key: str
    target_type: str
    target_id: UUID
    risk: str
    status: str
    payload_hash: str
    open_path_ids: tuple[int, ...]
    satisfied_path_id: int | None
    required_assurance: str
    expires_at: str


@dataclass(slots=True)
class ApprovalApiDependencies:
    service: ApprovalService


def _actor(request: Request) -> ActorContext:
    """The trusted actor. Never assembled from the request body."""
    actor = getattr(request.state, "actor", None)
    if not isinstance(actor, ActorContext):
        raise AuthenticationRequired
    return actor


def _dependencies(request: Request) -> ApprovalApiDependencies:
    dependencies = getattr(request.app.state, "approvals", None)
    if not isinstance(dependencies, ApprovalApiDependencies):
        raise AuthenticationRequired
    return dependencies


def _view(approval: ApprovalRequest) -> ApprovalView:
    return ApprovalView(
        approval_id=approval.approval_id,
        action_key=approval.action_key,
        target_type=approval.target_type,
        target_id=approval.target_id,
        risk=approval.risk.value,
        status=approval.status.value,
        payload_hash=approval.payload_hash,
        open_path_ids=approval.open_path_ids,
        satisfied_path_id=approval.satisfied_path_id,
        required_assurance=approval.required_assurance.value,
        expires_at=approval.expires_at.isoformat(),
    )


async def _decision_body(request: Request) -> ApprovalDecisionRequest:
    try:
        return ApprovalDecisionRequest.model_validate(await request.json())
    except (ValidationError, ValueError) as error:
        raise ApplicationError(
            code="VALIDATION_FAILED",
            message="The approval decision request is not valid.",
            status_code=422,
        ) from error


@router.get("/{approval_id}")
async def read_approval(approval_id: UUID, request: Request) -> Response:
    """Object authorization applies. A foreign identifier reads as absent."""
    actor = _actor(request)
    dependencies = _dependencies(request)
    approval = dependencies.service.repository.load(actor=actor, approval_id=approval_id)
    if approval is None:
        raise ApprovalNotFound
    return JSONResponse(
        status_code=status.HTTP_200_OK, content=_view(approval).model_dump(mode="json")
    )


@router.post("/{approval_id}/approve")
async def approve(approval_id: UUID, request: Request) -> Response:
    return await _decide(approval_id, request, DecisionType.APPROVED)


@router.post("/{approval_id}/reject")
async def reject(approval_id: UUID, request: Request) -> Response:
    return await _decide(approval_id, request, DecisionType.REJECTED)


@router.post("/{approval_id}/cancel")
async def cancel(approval_id: UUID, request: Request) -> Response:
    """Cancellation is the requester withdrawing, so it carries no payload hash."""
    actor = _actor(request)
    dependencies = _dependencies(request)
    approval = dependencies.service.cancel(actor=actor, approval_id=approval_id)
    return JSONResponse(
        status_code=status.HTTP_200_OK, content=_view(approval).model_dump(mode="json")
    )


async def _decide(approval_id: UUID, request: Request, decision: DecisionType) -> Response:
    actor = _actor(request)
    dependencies = _dependencies(request)
    body = await _decision_body(request)
    approval = dependencies.service.decide(
        actor=actor,
        approval_id=approval_id,
        decision=decision,
        payload_hash=body.payload_hash,
        idempotency_key=body.idempotency_key,
    )
    return JSONResponse(
        status_code=status.HTTP_200_OK, content=_view(approval).model_dump(mode="json")
    )
