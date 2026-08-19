"""`POST /chat` and the reconnectable `GET /chat/{operation_id}/events` stream.

SSE is framed directly on a Starlette `StreamingResponse` rather than through a
helper library, so the contract test can assert exact bytes.

Reconnect reads from the durable ledger, never from process memory, so a client
that reconnects after a worker restart still gets exactly the events it has not
seen. `Last-Event-ID` carries a stable `uuid5(operation, sequence)` value, which
is resolved back to a sequence — an unrecognised or forged id replays nothing
rather than replaying everything.

The actor always comes from the trusted Phase-01 boundary. `ChatRequest` forbids
extra fields, so a body carrying `tenant_id`, `roles` or `permissions` is a
validation error rather than an escalation.
"""

import json
from collections.abc import AsyncIterator, Callable
from dataclasses import dataclass
from datetime import datetime
from uuid import UUID

from fastapi import APIRouter, Request, Response, status
from fastapi.responses import JSONResponse, StreamingResponse
from pydantic import ValidationError

from app.agent.contracts import (
    TERMINAL_EVENT_TYPE,
    ChatAccepted,
    ChatRequest,
    StreamEvent,
)
from app.agent.errors import OperationNotFound
from app.agent.events import EventLedger
from app.agent.identity import derive_event_id
from app.agent.operations import OperationRepository
from app.agent.state import MAX_MESSAGES_PER_OPERATION
from app.contracts import ActorContext
from app.errors import ApplicationError
from app.observability.ports import TracePort

SSE_MEDIA_TYPE = "text/event-stream"
SSE_HEADERS = {
    "Cache-Control": "no-store",
    "Connection": "keep-alive",
    # Proxies that buffer would defeat streaming entirely.
    "X-Accel-Buffering": "no",
}
MAX_ACTIVE_OPERATIONS_PER_ACTOR = 8

router = APIRouter(prefix="/chat", tags=["chat"])


class TooManyActiveOperations(ApplicationError):
    """Per-actor concurrency bound from packet §12."""

    def __init__(self) -> None:
        super().__init__(
            code="RATE_LIMITED",
            message="Too many operations are already running for this actor.",
            status_code=429,
            retryable=True,
        )


@dataclass(slots=True)
class ChatDependencies:
    """Everything the endpoints need, injected so tests can fix the clock."""

    operations: OperationRepository
    events: EventLedger
    trace: TracePort
    clock: Callable[[], datetime]
    schedule: Callable[[ActorContext, UUID, str], None]


def format_sse_event(event: StreamEvent) -> str:
    """Exact SSE framing for one `StreamEvent v1`.

    `data` is compact single-line JSON, so an event never spans frames and message
    text containing newlines cannot forge a frame boundary.
    """
    payload = json.dumps(
        {
            "version": event.version,
            "event_id": str(event.event_id),
            "sequence": event.sequence,
            "operation_id": str(event.operation_id),
            "type": event.type.value,
            "data": event.data,
            "emitted_at": event.emitted_at.isoformat().replace("+00:00", "Z"),
        },
        separators=(",", ":"),
        sort_keys=True,
    )
    return f"id: {event.event_id}\nevent: {event.type.value}\ndata: {payload}\n\n"


def resolve_last_event_id(raw: str | None, operation_id: UUID, latest_sequence: int) -> int | None:
    """Turn a `Last-Event-ID` header into a replay boundary.

    Event ids are derived, so the sequence is recovered by re-deriving candidates
    rather than by trusting the header's shape. A forged or stale id matches
    nothing and replays nothing.
    """
    if not raw:
        return None
    try:
        supplied = UUID(raw.strip())
    except ValueError:
        return None
    for sequence in range(1, latest_sequence + 1):
        if derive_event_id(operation_id, sequence) == supplied:
            return sequence
    return None


def _actor(request: Request) -> ActorContext:
    """The trusted Phase-01 actor. Never assembled from the request body."""
    actor = getattr(request.state, "actor", None)
    if not isinstance(actor, ActorContext):
        from app.errors import AuthenticationRequired

        raise AuthenticationRequired
    return actor


def _dependencies(request: Request) -> ChatDependencies:
    dependencies = getattr(request.app.state, "chat", None)
    if not isinstance(dependencies, ChatDependencies):
        from app.errors import DependencyUnavailable

        raise DependencyUnavailable
    return dependencies


@router.post("", status_code=status.HTTP_202_ACCEPTED)
async def submit_chat(request: Request) -> Response:
    """Accept a chat submission and return the operation plus its stream URL."""
    actor = _actor(request)
    dependencies = _dependencies(request)

    try:
        body = await request.json()
    except ValueError:
        from app.errors import ApplicationError as _Error

        raise _Error(
            code="INPUT_INVALID", message="The request body is not valid JSON.", status_code=422
        ) from None

    try:
        chat_request = ChatRequest.model_validate(body)
    except ValidationError:
        # Field names are not echoed back: a rejected body must not become an oracle
        # for which privileged field names exist.
        raise ApplicationError(
            code="INPUT_INVALID",
            message="The chat request is not valid.",
            status_code=422,
        ) from None

    if dependencies.operations.active_count(actor=actor) >= MAX_ACTIVE_OPERATIONS_PER_ACTOR:
        raise TooManyActiveOperations

    created = dependencies.operations.create_or_restore(
        actor=actor,
        client_request_id=chat_request.client_request_id,
        conversation_id=chat_request.conversation_id,
        now=dependencies.clock(),
    )
    operation = created.operation

    dependencies.trace.record(
        "chat.submitted",
        operation_id=str(operation.operation_id),
        correlation_id=str(actor.correlation_id),
        conversation_id=str(operation.conversation_id),
        lifecycle_state=operation.state.value,
        outcome="CREATED" if created.created else "RESTORED",
    )

    if created.created:
        dependencies.schedule(actor, operation.operation_id, chat_request.message)

    accepted = ChatAccepted(
        operation_id=operation.operation_id,
        stream_url=f"/chat/{operation.operation_id}/events",
    )
    return JSONResponse(
        status_code=status.HTTP_202_ACCEPTED, content=accepted.model_dump(mode="json")
    )


@router.get("/{operation_id}/events")
async def stream_events(operation_id: UUID, request: Request) -> Response:
    """Replay the durable event ledger as SSE, honouring `Last-Event-ID`."""
    actor = _actor(request)
    dependencies = _dependencies(request)

    # Ownership is reauthorized here. A guessed or foreign id raises
    # OPERATION_NOT_FOUND, identical to an id that never existed.
    operation = dependencies.operations.load(actor=actor, operation_id=operation_id)

    stored = dependencies.events.read(actor=actor, operation_id=operation_id)
    latest_sequence = stored[-1].sequence if stored else 0
    after = resolve_last_event_id(
        request.headers.get("Last-Event-ID"), operation_id, latest_sequence
    )
    remaining = [event for event in stored if after is None or event.sequence > after]

    dependencies.trace.record(
        "chat.stream_opened",
        operation_id=str(operation_id),
        correlation_id=str(actor.correlation_id),
        lifecycle_state=operation.state.value,
        event_count=len(remaining),
        sse_reconnects=1 if after is not None else 0,
    )

    async def frames() -> AsyncIterator[bytes]:
        for event in remaining:
            if await request.is_disconnected():
                return
            yield format_sse_event(event).encode()
            if event.type is TERMINAL_EVENT_TYPE:
                return

    return StreamingResponse(frames(), media_type=SSE_MEDIA_TYPE, headers=dict(SSE_HEADERS))


__all__ = [
    "MAX_ACTIVE_OPERATIONS_PER_ACTOR",
    "MAX_MESSAGES_PER_OPERATION",
    "SSE_MEDIA_TYPE",
    "ChatDependencies",
    "OperationNotFound",
    "format_sse_event",
    "resolve_last_event_id",
    "router",
]
